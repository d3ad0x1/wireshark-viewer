// src/pcapParser.ts

export type L4Proto = "TCP" | "UDP" | "ICMP" | "OTHER";

export interface ParsedFrame {
  tsSec: number; // timestamp (seconds)
  tsUsec: number; // microseconds
  srcIp: string;
  dstIp: string;
  length: number;
  proto: L4Proto;
  srcPort?: number;
  dstPort?: number;
  tcpFlags?: number; // TCP flags (if TCP)
}

export interface ParsedSummary {
  frames: ParsedFrame[];
  totalPackets: number;
  totalBytes: number;
}

// сохраняем последний буфер для HTTP-экстракции
let lastBuffer: ArrayBuffer | null = null;

/* ===== PCAP / PCAPNG format detection ===== */

function detectFormat(buffer: ArrayBuffer): "pcap" | "pcapng" | "unknown" {
  const dv = new DataView(buffer);
  if (dv.byteLength < 4) return "unknown";

  const magicRawBE = dv.getUint32(0, false);

  if (magicRawBE === 0x0a0d0d0a) {
    return "pcapng";
  }

  const magicBE = dv.getUint32(0, false);
  const magicLE = dv.getUint32(0, true);

  const PCAP_MAGICS = [
    0xa1b2c3d4,
    0xd4c3b2a1,
    0xa1b23c4d,
    0x4d3cb2a1,
  ];

  if (PCAP_MAGICS.includes(magicBE) || PCAP_MAGICS.includes(magicLE)) {
    return "pcap";
  }

  return "unknown";
}

function detectPcapEndianness(buffer: ArrayBuffer): {
  littleEndian: boolean;
  nano: boolean;
} {
  const dv = new DataView(buffer);
  const magicBE = dv.getUint32(0, false);
  const magicLE = dv.getUint32(0, true);

  switch (magicBE) {
    case 0xa1b2c3d4:
      return { littleEndian: false, nano: false };
    case 0xa1b23c4d:
      return { littleEndian: false, nano: true };
  }

  switch (magicLE) {
    case 0xd4c3b2a1:
      return { littleEndian: true, nano: false };
    case 0x4d3cb2a1:
      return { littleEndian: true, nano: true };
  }

  return { littleEndian: true, nano: false };
}

function readIPv4(dv: DataView, offset: number): string {
  const a = dv.getUint8(offset);
  const b = dv.getUint8(offset + 1);
  const c = dv.getUint8(offset + 2);
  const d = dv.getUint8(offset + 3);
  return `${a}.${b}.${c}.${d}`;
}

/* ===== Classic PCAP (Ethernet + IPv4) ===== */

function parseClassicPcap(buffer: ArrayBuffer): ParsedSummary {
  const dv = new DataView(buffer);
  const { littleEndian } = detectPcapEndianness(buffer);

  const globalHeaderSize = 24;
  if (dv.byteLength < globalHeaderSize) {
    throw new Error("PCAP file is too short (no global header)");
  }

  let offset = globalHeaderSize;
  const frames: ParsedFrame[] = [];
  let totalPackets = 0;
  let totalBytes = 0;

  while (offset + 16 <= dv.byteLength) {
    const tsSec = dv.getUint32(offset + 0, littleEndian);
    const tsUsec = dv.getUint32(offset + 4, littleEndian);
    const inclLen = dv.getUint32(offset + 8, littleEndian);
    const origLen = dv.getUint32(offset + 12, littleEndian);

    const packetHeaderSize = 16;
    const dataOffset = offset + packetHeaderSize;

    if (dataOffset + inclLen > dv.byteLength) {
      break;
    }

    if (inclLen < 14) {
      offset = dataOffset + inclLen;
      continue;
    }

    const ethOffset = dataOffset;
    const etherType = dv.getUint16(ethOffset + 12, false);

    if (etherType !== 0x0800) {
      offset = dataOffset + inclLen;
      continue;
    }

    const ipOffset = ethOffset + 14;
    if (dataOffset + inclLen < ipOffset + 20) {
      offset = dataOffset + inclLen;
      continue;
    }

    const verIhl = dv.getUint8(ipOffset);
    const version = verIhl >> 4;
    const ihl = (verIhl & 0x0f) * 4;

    if (version !== 4 || ihl < 20) {
      offset = dataOffset + inclLen;
      continue;
    }

    const totalLen = dv.getUint16(ipOffset + 2, false);
    const protoNum = dv.getUint8(ipOffset + 9);

    const srcIp = readIPv4(dv, ipOffset + 12);
    const dstIp = readIPv4(dv, ipOffset + 16);

    let proto: L4Proto = "OTHER";
    if (protoNum === 6) proto = "TCP";
    else if (protoNum === 17) proto = "UDP";
    else if (protoNum === 1) proto = "ICMP";

    let srcPort: number | undefined;
    let dstPort: number | undefined;
    let tcpFlags: number | undefined;

    const l4Offset = ipOffset + ihl;
    if (proto === "TCP" || proto === "UDP") {
      if (dataOffset + inclLen >= l4Offset + 4) {
        srcPort = dv.getUint16(l4Offset + 0, false);
        dstPort = dv.getUint16(l4Offset + 2, false);
      }
    }
    if (proto === "TCP") {
      if (dataOffset + inclLen >= l4Offset + 14) {
        tcpFlags = dv.getUint8(l4Offset + 13);
      }
    }

    const length = totalLen || inclLen || origLen;

    frames.push({
      tsSec,
      tsUsec,
      srcIp,
      dstIp,
      length,
      proto,
      srcPort,
      dstPort,
      tcpFlags,
    });

    totalPackets += 1;
    totalBytes += length;

    offset = dataOffset + inclLen;
  }

  return {
    frames,
    totalPackets,
    totalBytes,
  };
}

/* ===== PCAPNG ===== */

function detectPcapNgEndianness(dv: DataView): boolean {
  if (dv.byteLength < 12) return true;

  const magicBE = dv.getUint32(8, false);
  const magicLE = dv.getUint32(8, true);

  const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
  if (magicBE === BYTE_ORDER_MAGIC) return false;
  if (magicLE === BYTE_ORDER_MAGIC) return true;

  return true;
}

function parsePcapNg(buffer: ArrayBuffer): ParsedSummary {
  const dv = new DataView(buffer);
  const littleEndian = detectPcapNgEndianness(dv);

  const len = dv.byteLength;
  if (len < 28) {
    throw new Error("PCAPNG file is too short");
  }

  const firstBlockType = dv.getUint32(0, false);
  if (firstBlockType !== 0x0a0d0d0a) {
    throw new Error("PCAPNG: first block is not Section Header Block");
  }

  const ifaceLinkType: Record<number, number> = {};
  let currentIfaceIndex = 0;

  const frames: ParsedFrame[] = [];
  let totalPackets = 0;
  let totalBytes = 0;

  let offset = 0;

  while (offset + 12 <= len) {
    const blockType = dv.getUint32(offset, littleEndian);
    const blockTotalLength = dv.getUint32(offset + 4, littleEndian);

    if (blockTotalLength < 12 || offset + blockTotalLength > len) {
      break;
    }

    const bodyOffset = offset + 8;
    const bodyLen = blockTotalLength - 12;

    switch (blockType) {
      case 0x0a0d0d0a:
        // SHB
        break;

      case 0x00000001: {
        // Interface Description Block
        const linktype = dv.getUint16(bodyOffset + 0, littleEndian);
        ifaceLinkType[currentIfaceIndex] = linktype;
        currentIfaceIndex += 1;
        break;
      }

      case 0x00000006: {
        // Enhanced Packet Block
        if (bodyLen < 20) break;

        const ifaceId = dv.getUint32(bodyOffset + 0, littleEndian);
        const tsHigh = dv.getUint32(bodyOffset + 4, littleEndian);
        const tsLow = dv.getUint32(bodyOffset + 8, littleEndian);
        const capturedLen = dv.getUint32(bodyOffset + 12, littleEndian);
        const origLen = dv.getUint32(bodyOffset + 16, littleEndian);

        const linktype = ifaceLinkType[ifaceId] ?? 1;

        const packetDataOffset = bodyOffset + 20;
        const packetDataEnd = packetDataOffset + capturedLen;
        const blockEnd = offset + blockTotalLength;

        if (packetDataEnd > blockEnd - 4) {
          break;
        }

        if (linktype !== 1) {
          break;
        }

        const ethOffset = packetDataOffset;
        if (capturedLen < 14) break;

        const etherType = dv.getUint16(ethOffset + 12, false);
        if (etherType !== 0x0800) break;

        const ipOffset = ethOffset + 14;
        if (packetDataEnd < ipOffset + 20) break;

        const verIhl = dv.getUint8(ipOffset);
        const version = verIhl >> 4;
        const ihl = (verIhl & 0x0f) * 4;
        if (version !== 4 || ihl < 20) break;

        const totalLen = dv.getUint16(ipOffset + 2, false);
        const protoNum = dv.getUint8(ipOffset + 9);

        const srcIp = readIPv4(dv, ipOffset + 12);
        const dstIp = readIPv4(dv, ipOffset + 16);

        let proto: L4Proto = "OTHER";
        if (protoNum === 6) proto = "TCP";
        else if (protoNum === 17) proto = "UDP";
        else if (protoNum === 1) proto = "ICMP";

        let srcPort: number | undefined;
        let dstPort: number | undefined;
        let tcpFlags: number | undefined;

        const l4Offset = ipOffset + ihl;
        if (proto === "TCP" || proto === "UDP") {
          if (packetDataEnd >= l4Offset + 4) {
            srcPort = dv.getUint16(l4Offset + 0, false);
            dstPort = dv.getUint16(l4Offset + 2, false);
          }
        }
        if (proto === "TCP") {
          if (packetDataEnd >= l4Offset + 14) {
            tcpFlags = dv.getUint8(l4Offset + 13);
          }
        }

        const ts64 = tsHigh * 4294967296 + tsLow;
        const tsSec = Math.floor(ts64 / 1_000_000);
        const tsUsec = ts64 % 1_000_000;

        const length = totalLen || capturedLen || origLen;

        frames.push({
          tsSec,
          tsUsec,
          srcIp,
          dstIp,
          length,
          proto,
          srcPort,
          dstPort,
          tcpFlags,
        });

        totalPackets += 1;
        totalBytes += length;

        break;
      }

      default:
        break;
    }

    offset += blockTotalLength;
  }

  return {
    frames,
    totalPackets,
    totalBytes,
  };
}

/* ===== Public parse API ===== */

export async function parsePcapFile(buffer: ArrayBuffer): Promise<ParsedSummary> {
  lastBuffer = buffer;
  const fmt = detectFormat(buffer);

  if (fmt === "pcap") {
    return parseClassicPcap(buffer);
  }

  if (fmt === "pcapng") {
    return parsePcapNg(buffer);
  }

  throw new Error("Unknown or unsupported capture format (not PCAP/PCAPNG).");
}

/* ===== Aggregations & analytics ===== */

export interface IpAgg {
  ip: string;
  packets: number;
  bytes: number;
  firstTs: number;
  lastTs: number;
  pps: number;
  uniqueDstIps: number;
  uniqueDstPorts: number;
  synCount: number;
}

export function buildIpAgg(summary: ParsedSummary): Record<string, IpAgg> {
  const map: Record<string, IpAgg> = {};

  for (const f of summary.frames) {
    const ip = f.srcIp;
    if (!map[ip]) {
      map[ip] = {
        ip,
        packets: 0,
        bytes: 0,
        firstTs: f.tsSec,
        lastTs: f.tsSec,
        pps: 0,
        uniqueDstIps: 0,
        uniqueDstPorts: 0,
        synCount: 0,
      };
    }
    const agg = map[ip];
    agg.packets += 1;
    agg.bytes += f.length;
    if (f.tsSec < agg.firstTs) agg.firstTs = f.tsSec;
    if (f.tsSec > agg.lastTs) agg.lastTs = f.tsSec;
  }

  const dstIpSets: Record<string, Set<string>> = {};
  const dstPortSets: Record<string, Set<number>> = {};
  const synCounts: Record<string, number> = {};

  for (const f of summary.frames) {
    const ip = f.srcIp;
    if (!map[ip]) continue;

    if (!dstIpSets[ip]) dstIpSets[ip] = new Set();
    if (!dstPortSets[ip]) dstPortSets[ip] = new Set();
    if (!synCounts[ip]) synCounts[ip] = 0;

    dstIpSets[ip].add(f.dstIp);

    const port = f.dstPort ?? f.srcPort;
    if (port != null) dstPortSets[ip].add(port);

    if (f.proto === "TCP" && f.tcpFlags != null) {
      const flags = f.tcpFlags;
      const syn = (flags & 0x02) !== 0;
      const ack = (flags & 0x10) !== 0;
      if (syn && !ack) {
        synCounts[ip] += 1;
      }
    }
  }

  for (const ip of Object.keys(map)) {
    const agg = map[ip];
    const dur = Math.max(1, agg.lastTs - agg.firstTs + 1);
    agg.pps = agg.packets / dur;
    agg.uniqueDstIps = dstIpSets[ip]?.size || 0;
    agg.uniqueDstPorts = dstPortSets[ip]?.size || 0;
    agg.synCount = synCounts[ip] || 0;
  }

  return map;
}

export function buildIpStats(summary: ParsedSummary) {
  const agg = buildIpAgg(summary);
  return Object.values(agg).map((a) => ({
    ip: a.ip,
    packets: a.packets,
    bytes: a.bytes,
  }));
}

export function buildTimeline(summary: ParsedSummary) {
  const buckets = new Map<number, number>();

  for (const f of summary.frames) {
    const t = f.tsSec;
    buckets.set(t, (buckets.get(t) || 0) + 1);
  }

  const entries = Array.from(buckets.entries()).sort((a, b) => a[0] - b[0]);

  return entries.map(([tsSec, count]) => ({
    tsSec,
    count,
  }));
}

/* ===== Scans / DoS detection ===== */

export interface ScanEntry {
  ip: string;
  packets: number;
  bytes: number;
  pps: number;
  uniqueDstPorts: number;
  uniqueDstIps: number;
  synCount: number;
  reasons: string[];
}

export function detectScansAndDos(summary: ParsedSummary): ScanEntry[] {
  const agg = buildIpAgg(summary);

  const MIN_PACKETS = 50;
  const HIGH_PPS = 200;
  const MANY_PORTS = 20;
  const MANY_SYN = 100;
  const MANY_TARGETS = 20;

  const res: ScanEntry[] = [];

  for (const a of Object.values(agg)) {
    if (a.packets < MIN_PACKETS) continue;

    const reasons: string[] = [];

    if (a.pps >= HIGH_PPS) reasons.push("reason.HIGH_PPS");
    if (a.uniqueDstPorts >= MANY_PORTS) reasons.push("reason.MANY_PORTS");
    if (a.synCount >= MANY_SYN) reasons.push("reason.MANY_SYN");
    if (a.uniqueDstIps >= MANY_TARGETS) reasons.push("reason.MANY_TARGETS");

    if (!reasons.length) continue;

    res.push({
      ip: a.ip,
      packets: a.packets,
      bytes: a.bytes,
      pps: a.pps,
      uniqueDstPorts: a.uniqueDstPorts,
      uniqueDstIps: a.uniqueDstIps,
      synCount: a.synCount,
      reasons,
    });
  }

  res.sort((x, y) => {
    const sx = x.reasons.length;
    const sy = y.reasons.length;
    if (sx !== sy) return sy - sx;
    return y.pps - x.pps;
  });

  return res;
}

/* ===== SIP stats ===== */

export interface SipHostStat {
  ip: string;
  packets: number;
  bytes: number;
}

export interface SipStats {
  totalPackets: number;
  totalBytes: number;
  topSources: SipHostStat[];
  topDests: SipHostStat[];
}

export function computeSipStats(summary: ParsedSummary): SipStats {
  const SIP_PORTS = new Set([5060, 5061]);

  let totalPackets = 0;
  let totalBytes = 0;

  const srcMap: Record<string, SipHostStat> = {};
  const dstMap: Record<string, SipHostStat> = {};

  for (const f of summary.frames) {
    if (f.proto !== "UDP" && f.proto !== "TCP") continue;

    const ports = [f.srcPort, f.dstPort].filter((p) => p != null) as number[];
    if (!ports.some((p) => SIP_PORTS.has(p))) continue;

    totalPackets += 1;
    totalBytes += f.length;

    if (!srcMap[f.srcIp]) {
      srcMap[f.srcIp] = { ip: f.srcIp, packets: 0, bytes: 0 };
    }
    if (!dstMap[f.dstIp]) {
      dstMap[f.dstIp] = { ip: f.dstIp, packets: 0, bytes: 0 };
    }

    srcMap[f.srcIp].packets += 1;
    srcMap[f.srcIp].bytes += f.length;

    dstMap[f.dstIp].packets += 1;
    dstMap[f.dstIp].bytes += f.length;
  }

  const topSources = Object.values(srcMap).sort(
    (a, b) => b.packets - a.packets
  );
  const topDests = Object.values(dstMap).sort((a, b) => b.packets - a.packets);

  return {
    totalPackets,
    totalBytes,
    topSources: topSources.slice(0, 10),
    topDests: topDests.slice(0, 10),
  };
}

/* ===== Cameras heuristics ===== */

export interface CameraEntry {
  ip: string;
  score: number;
  reasons: string[];
}

export function detectCameras(summary: ParsedSummary): CameraEntry[] {
  const CAMERA_PORTS = new Set([
    554,
    8554,
    8000,
    37777,
    5000,
    9000,
    8899,
  ]);

  const agg = buildIpAgg(summary);

  const hits: Record<
    string,
    {
      camPorts: number;
      udpPackets: number;
    }
  > = {};

  for (const f of summary.frames) {
    const ip = f.srcIp;
    if (!hits[ip]) hits[ip] = { camPorts: 0, udpPackets: 0 };

    const ports = [f.srcPort, f.dstPort].filter((p) => p != null) as number[];
    if (ports.some((p) => CAMERA_PORTS.has(p))) {
      hits[ip].camPorts += 1;
    }

    if (f.proto === "UDP") {
      hits[ip].udpPackets += 1;
    }
  }

  const res: CameraEntry[] = [];

  for (const [ip, h] of Object.entries(hits)) {
    const a = agg[ip];
    if (!a) continue;

    let score = 0;
    const reasons: string[] = [];

    if (h.camPorts >= 10) {
      score += h.camPorts;
      reasons.push("many RTSP/Camera ports");
    }
    if (h.udpPackets >= 100 && a.pps >= 20) {
      score += 20;
      reasons.push("udp stream-ish traffic");
    }

    if (score >= 10) {
      res.push({
        ip,
        score,
        reasons,
      });
    }
  }

  res.sort((a, b) => b.score - a.score);
  return res;
}

/* ===== MITRE hints ===== */

export interface AttackHint {
  mitreId: string;
  severity: "low" | "medium" | "high";
  reasonKey: string;
  ips: string[];
}

export function buildMitreHints(
  scans: ScanEntry[],
  sip: SipStats,
  cameras: CameraEntry[]
): AttackHint[] {
  const hints: AttackHint[] = [];

  const scanIps = scans
    .filter((s) => s.reasons.includes("reason.MANY_PORTS"))
    .map((s) => s.ip);
  if (scanIps.length) {
    hints.push({
      mitreId: "T1046",
      severity: scanIps.length > 3 ? "high" : "medium",
      reasonKey: "mitre.network_scan",
      ips: scanIps.slice(0, 10),
    });
  }

  const dosIps = scans
    .filter(
      (s) =>
        s.reasons.includes("reason.HIGH_PPS") ||
        s.reasons.includes("reason.MANY_TARGETS")
    )
    .map((s) => s.ip);
  if (dosIps.length) {
    hints.push({
      mitreId: "T1499",
      severity: "high",
      reasonKey: "mitre.dos",
      ips: dosIps.slice(0, 10),
    });
  }

  return hints;
}

/* ===== Storyline ===== */

export type StoryKind = "scan" | "dos" | "sip" | "camera";

export interface StoryItem {
  tsSec: number;
  ip: string | null;
  kind: StoryKind;
}

export function buildStoryline(
  summary: ParsedSummary,
  scans: ScanEntry[],
  sip: SipStats,
  cameras: CameraEntry[]
): StoryItem[] {
  const ipAgg = buildIpAgg(summary);
  const items: StoryItem[] = [];

  const nowTs =
    summary.frames.length > 0 ? summary.frames[0].tsSec : Math.floor(Date.now() / 1000);

  for (const s of scans) {
    const a = ipAgg[s.ip];
    items.push({
      tsSec: a ? a.firstTs : nowTs,
      ip: s.ip,
      kind: "scan",
    });
  }

  for (const s of scans) {
    if (
      s.reasons.includes("reason.HIGH_PPS") ||
      s.reasons.includes("reason.MANY_TARGETS")
    ) {
      const a = ipAgg[s.ip];
      items.push({
        tsSec: a ? a.firstTs : nowTs,
        ip: s.ip,
        kind: "dos",
      });
    }
  }

  if (sip.totalPackets > 0) {
    const ts =
      summary.frames.length > 0 ? summary.frames[0].tsSec : nowTs;
    items.push({
      tsSec: ts,
      ip: null,
      kind: "sip",
    });
  }

  for (const c of cameras) {
    const a = ipAgg[c.ip];
    items.push({
      tsSec: a ? a.firstTs : nowTs,
      ip: c.ip,
      kind: "camera",
    });
  }

  items.sort((a, b) => a.tsSec - b.tsSec);
  return items;
}

/* ===== IP details (drilldown) ===== */

export interface IpDetail {
  ip: string;
  outboundPackets: number;
  outboundBytes: number;
  inboundPackets: number;
  inboundBytes: number;
  firstTs: number;
  lastTs: number;
  pps: number;
  topTalkedTo: { ip: string; packets: number; bytes: number }[];
  topDstPorts: { port: number; packets: number; bytes: number }[];
}

export function buildIpDetails(
  summary: ParsedSummary
): Record<string, IpDetail> {
  const frames = summary.frames;

  type Stat = {
    outboundPackets: number;
    outboundBytes: number;
    inboundPackets: number;
    inboundBytes: number;
    firstTs: number;
    lastTs: number;
  };

  const base: Record<string, Stat> = {};
  const peers: Record<string, Record<string, { packets: number; bytes: number }>> =
    {};
  const ports: Record<string, Record<number, { packets: number; bytes: number }>> =
    {};

  for (const f of frames) {
    const len = f.length;

    if (!base[f.srcIp]) {
      base[f.srcIp] = {
        outboundPackets: 0,
        outboundBytes: 0,
        inboundPackets: 0,
        inboundBytes: 0,
        firstTs: f.tsSec,
        lastTs: f.tsSec,
      };
    }
    const bs = base[f.srcIp];
    bs.outboundPackets += 1;
    bs.outboundBytes += len;
    if (f.tsSec < bs.firstTs) bs.firstTs = f.tsSec;
    if (f.tsSec > bs.lastTs) bs.lastTs = f.tsSec;

    if (!base[f.dstIp]) {
      base[f.dstIp] = {
        outboundPackets: 0,
        outboundBytes: 0,
        inboundPackets: 0,
        inboundBytes: 0,
        firstTs: f.tsSec,
        lastTs: f.tsSec,
      };
    }
    const bd = base[f.dstIp];
    bd.inboundPackets += 1;
    bd.inboundBytes += len;
    if (f.tsSec < bd.firstTs) bd.firstTs = f.tsSec;
    if (f.tsSec > bd.lastTs) bd.lastTs = f.tsSec;

    if (!peers[f.srcIp]) peers[f.srcIp] = {};
    if (!peers[f.srcIp][f.dstIp]) {
      peers[f.srcIp][f.dstIp] = { packets: 0, bytes: 0 };
    }
    peers[f.srcIp][f.dstIp].packets += 1;
    peers[f.srcIp][f.dstIp].bytes += len;

    const port = f.dstPort ?? f.srcPort;
    if (port != null) {
      if (!ports[f.srcIp]) ports[f.srcIp] = {};
      if (!ports[f.srcIp][port]) {
        ports[f.srcIp][port] = { packets: 0, bytes: 0 };
      }
      ports[f.srcIp][port].packets += 1;
      ports[f.srcIp][port].bytes += len;
    }
  }

  const res: Record<string, IpDetail> = {};

  for (const [ip, s] of Object.entries(base)) {
    const dur = Math.max(1, s.lastTs - s.firstTs + 1);
    const pps = s.outboundPackets / dur;

    const peersMap = peers[ip] || {};
    const portsMap = ports[ip] || {};

    const topTalkedTo = Object.entries(peersMap)
      .map(([p, v]) => ({
        ip: p,
        packets: v.packets,
        bytes: v.bytes,
      }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 10);

    const topDstPorts = Object.entries(portsMap)
      .map(([p, v]) => ({
        port: Number(p),
        packets: v.packets,
        bytes: v.bytes,
      }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 10);

    res[ip] = {
      ip,
      outboundPackets: s.outboundPackets,
      outboundBytes: s.outboundBytes,
      inboundPackets: s.inboundPackets,
      inboundBytes: s.inboundBytes,
      firstTs: s.firstTs,
      lastTs: s.lastTs,
      pps,
      topTalkedTo,
      topDstPorts,
    };
  }

  return res;
}

/* ===== HTTP extraction (simple single-packet responses) ===== */

export interface HttpObject {
  id: number;
  tsSec: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  mime: string;
  filename?: string;
  length: number;
  data: Uint8Array;
}

export async function extractHttpObjects(): Promise<HttpObject[]> {
  if (!lastBuffer) {
    throw new Error("No capture parsed yet");
  }
  const buffer = lastBuffer;
  const fmt = detectFormat(buffer);

  if (fmt === "pcap") {
    return extractHttpFromPcap(buffer);
  }
  if (fmt === "pcapng") {
    return extractHttpFromPcapNg(buffer);
  }
  throw new Error("Unsupported capture format for HTTP extraction");
}

function parseHttpFromPayload(
  dv: DataView,
  absOffset: number,
  maxLen: number
): { mime: string; filename?: string; length: number; headerBytes: number } | null {
  if (maxLen <= 0) return null;

  const maxHeader = Math.min(maxLen, 8192);
  const bytes = new Uint8Array(dv.buffer, absOffset, maxHeader);
  const text = new TextDecoder("ascii").decode(bytes);

  if (!text.startsWith("HTTP/1.0 ") && !text.startsWith("HTTP/1.1 ")) {
    return null;
  }

  const headerEnd = text.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;

  const headerText = text.slice(0, headerEnd);
  const headerBytes = headerEnd + 4;

  let mime = "application/octet-stream";
  let length: number | null = null;
  let filename: string | undefined;

  const lines = headerText.split("\r\n");
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();

    if (name === "content-type") {
      mime = value.split(";")[0].trim() || mime;
    } else if (name === "content-length") {
      const n = parseInt(value, 10);
      if (!Number.isNaN(n) && n > 0) {
        length = n;
      }
    } else if (name === "content-disposition") {
      const m = /filename="?([^";]+)"?/i.exec(value);
      if (m) {
        filename = m[1];
      }
    }
  }

  if (length == null) return null;
  if (headerBytes + length > maxLen) return null;

  return { mime, filename, length, headerBytes };
}

/* PCAP -> HTTP */

function extractHttpFromPcap(buffer: ArrayBuffer): HttpObject[] {
  const dv = new DataView(buffer);
  const { littleEndian } = detectPcapEndianness(buffer);

  const globalHeaderSize = 24;
  if (dv.byteLength < globalHeaderSize) return [];

  const objects: HttpObject[] = [];
  let offset = globalHeaderSize;
  let id = 1;

  while (offset + 16 <= dv.byteLength) {
    const tsSec = dv.getUint32(offset + 0, littleEndian);
    const tsUsec = dv.getUint32(offset + 4, littleEndian);
    const inclLen = dv.getUint32(offset + 8, littleEndian);
    const origLen = dv.getUint32(offset + 12, littleEndian);

    const packetHeaderSize = 16;
    const dataOffset = offset + packetHeaderSize;
    const packetEnd = dataOffset + inclLen;

    if (packetEnd > dv.byteLength) break;
    if (inclLen < 54) {
      offset = packetEnd;
      continue;
    }

    const ethOffset = dataOffset;
    const etherType = dv.getUint16(ethOffset + 12, false);
    if (etherType !== 0x0800) {
      offset = packetEnd;
      continue;
    }

    const ipOffset = ethOffset + 14;
    const verIhl = dv.getUint8(ipOffset);
    const version = verIhl >> 4;
    const ihl = (verIhl & 0x0f) * 4;
    if (version !== 4 || ihl < 20) {
      offset = packetEnd;
      continue;
    }

    const protoNum = dv.getUint8(ipOffset + 9);
    if (protoNum !== 6) {
      offset = packetEnd;
      continue;
    }

    const srcIp = readIPv4(dv, ipOffset + 12);
    const dstIp = readIPv4(dv, ipOffset + 16);

    const tcpOffset = ipOffset + ihl;
    if (packetEnd < tcpOffset + 20) {
      offset = packetEnd;
      continue;
    }

    const srcPort = dv.getUint16(tcpOffset + 0, false);
    const dstPort = dv.getUint16(tcpOffset + 2, false);

    if (![80, 8080, 8000].includes(srcPort) && ![80, 8080, 8000].includes(dstPort)) {
      offset = packetEnd;
      continue;
    }

    const dataOffsetAndFlags = dv.getUint8(tcpOffset + 12);
    const dataOffsetWords = (dataOffsetAndFlags >> 4) & 0x0f;
    const tcpHeaderLen = dataOffsetWords * 4;
    const payloadOffset = tcpOffset + tcpHeaderLen;

    if (payloadOffset >= packetEnd) {
      offset = packetEnd;
      continue;
    }

    const payloadLen = packetEnd - payloadOffset;
    const http = parseHttpFromPayload(dv, payloadOffset, payloadLen);
    if (!http) {
      offset = packetEnd;
      continue;
    }

    const bodyStart = payloadOffset + http.headerBytes;
    const bodyEnd = bodyStart + http.length;
    if (bodyEnd > packetEnd) {
      offset = packetEnd;
      continue;
    }

    const data = new Uint8Array(buffer.slice(bodyStart, bodyEnd));

    objects.push({
      id: id++,
      tsSec,
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      mime: http.mime,
      filename: http.filename,
      length: http.length,
      data,
    });

    offset = packetEnd;
  }

  return objects;
}

/* PCAPNG -> HTTP */

function extractHttpFromPcapNg(buffer: ArrayBuffer): HttpObject[] {
  const dv = new DataView(buffer);
  const littleEndian = detectPcapNgEndianness(dv);
  const len = dv.byteLength;
  const objects: HttpObject[] = [];
  let offset = 0;
  let id = 1;

  const ifaceLinkType: Record<number, number> = {};
  let ifaceIndex = 0;

  while (offset + 12 <= len) {
    const blockType = dv.getUint32(offset, littleEndian);
    const blockTotalLength = dv.getUint32(offset + 4, littleEndian);
    if (blockTotalLength < 12 || offset + blockTotalLength > len) break;

    const bodyOffset = offset + 8;
    const bodyLen = blockTotalLength - 12;

    if (blockType === 0x00000001) {
      const linktype = dv.getUint16(bodyOffset + 0, littleEndian);
      ifaceLinkType[ifaceIndex++] = linktype;
    } else if (blockType === 0x00000006) {
      if (bodyLen < 20) {
        offset += blockTotalLength;
        continue;
      }

      const ifaceId = dv.getUint32(bodyOffset + 0, littleEndian);
      const tsHigh = dv.getUint32(bodyOffset + 4, littleEndian);
      const tsLow = dv.getUint32(bodyOffset + 8, littleEndian);
      const capturedLen = dv.getUint32(bodyOffset + 12, littleEndian);
      const origLen = dv.getUint32(bodyOffset + 16, littleEndian);

      const linktype = ifaceLinkType[ifaceId] ?? 1;
      if (linktype !== 1) {
        offset += blockTotalLength;
        continue;
      }

      const packetDataOffset = bodyOffset + 20;
      const packetDataEnd = packetDataOffset + capturedLen;
      const blockEnd = offset + blockTotalLength;
      if (packetDataEnd > blockEnd - 4) {
        offset += blockTotalLength;
        continue;
      }

      if (capturedLen < 54) {
        offset += blockTotalLength;
        continue;
      }

      const ethOffset = packetDataOffset;
      const etherType = dv.getUint16(ethOffset + 12, false);
      if (etherType !== 0x0800) {
        offset += blockTotalLength;
        continue;
      }

      const ipOffset = ethOffset + 14;
      const verIhl = dv.getUint8(ipOffset);
      const version = verIhl >> 4;
      const ihl = (verIhl & 0x0f) * 4;
      if (version !== 4 || ihl < 20) {
        offset += blockTotalLength;
        continue;
      }

      const protoNum = dv.getUint8(ipOffset + 9);
      if (protoNum !== 6) {
        offset += blockTotalLength;
        continue;
      }

      const srcIp = readIPv4(dv, ipOffset + 12);
      const dstIp = readIPv4(dv, ipOffset + 16);

      const tcpOffset = ipOffset + ihl;
      if (packetDataEnd < tcpOffset + 20) {
        offset += blockTotalLength;
        continue;
      }

      const srcPort = dv.getUint16(tcpOffset + 0, false);
      const dstPort = dv.getUint16(tcpOffset + 2, false);

      if (![80, 8080, 8000].includes(srcPort) && ![80, 8080, 8000].includes(dstPort)) {
        offset += blockTotalLength;
        continue;
      }

      const dataOffsetAndFlags = dv.getUint8(tcpOffset + 12);
      const dataOffsetWords = (dataOffsetAndFlags >> 4) & 0x0f;
      const tcpHeaderLen = dataOffsetWords * 4;
      const payloadOffset = tcpOffset + tcpHeaderLen;
      if (payloadOffset >= packetDataEnd) {
        offset += blockTotalLength;
        continue;
      }

      const payloadLen = packetDataEnd - payloadOffset;
      const http = parseHttpFromPayload(dv, payloadOffset, payloadLen);
      if (!http) {
        offset += blockTotalLength;
        continue;
      }

      const bodyStart = payloadOffset + http.headerBytes;
      const bodyEnd = bodyStart + http.length;
      if (bodyEnd > packetDataEnd) {
        offset += blockTotalLength;
        continue;
      }

      const ts64 = tsHigh * 4294967296 + tsLow;
      const tsSec = Math.floor(ts64 / 1_000_000);

      const data = new Uint8Array(buffer.slice(bodyStart, bodyEnd));

      objects.push({
        id: id++,
        tsSec,
        srcIp,
        dstIp,
        srcPort,
        dstPort,
        mime: http.mime,
        filename: http.filename,
        length: http.length,
        data,
      });
    }

    offset += blockTotalLength;
  }

  return objects;
}
