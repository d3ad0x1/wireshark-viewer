<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from "vue";
import Chart from "chart.js/auto";
import { createI18n, type Lang } from "./i18n";
import {
  parsePcapFile,
  buildIpStats,
  buildTimeline,
  type ParsedSummary,
  detectScansAndDos,
  type ScanEntry,
  computeSipStats,
  type SipStats,
  detectCameras,
  type CameraEntry,
  buildMitreHints,
  type AttackHint,
  buildStoryline,
  type StoryItem,
  buildIpDetails,
  type IpDetail,
  extractHttpObjects,
  type HttpObject,
} from "./pcapParser";

const i18n = createI18n("en");
const currentLang = ref<Lang>("en");

const setLang = (lang: Lang) => {
  currentLang.value = lang;
  i18n.setLang(lang);
};
const t = (key: string) => i18n.t(key);

// file / state
const selectedFile = ref<File | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
const parsed = ref<ParsedSummary | null>(null);

// filters
const filterIp = ref("");
const showOnlySuspicious = ref(false);

// timeline chart
const timelineCanvas = ref<HTMLCanvasElement | null>(null);
const timelineChart = ref<any | null>(null);

// IP details
const ipDetailsMap = computed<Record<string, IpDetail>>(() => {
  if (!parsed.value) return {};
  return buildIpDetails(parsed.value);
});
const selectedIp = ref<string | null>(null);

// HTTP objects
const httpObjects = ref<HttpObject[] | null>(null);
const httpLoading = ref(false);
const httpError = ref<string | null>(null);

function onFileChange(e: Event) {
  const target = e.target as HTMLInputElement;
  const file = target.files?.[0] || null;
  selectedFile.value = file;
  parsed.value = null;
  error.value = null;
  selectedIp.value = null;
  httpObjects.value = null;
  httpError.value = null;
  destroyTimelineChart();
}

async function analyze() {
  if (!selectedFile.value) {
    error.value = t("noFile");
    return;
  }

  loading.value = true;
  error.value = null;
  parsed.value = null;
  selectedIp.value = null;
  httpObjects.value = null;
  httpError.value = null;
  destroyTimelineChart();

  try {
    const buf = await selectedFile.value.arrayBuffer();
    const summary = await parsePcapFile(buf);
    parsed.value = summary;
  } catch (e: any) {
    error.value = e?.message || "Unknown error";
  } finally {
    loading.value = false;
  }
}

// Basic stats
const totalPackets = computed(
  () => parsed.value?.totalPackets || 0
);
const totalBytes = computed(
  () => parsed.value?.totalBytes || 0
);

function formatBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

// Heavy talkers
const ipStats = computed(() => {
  if (!parsed.value) return [];
  const raw = buildIpStats(parsed.value);
  let arr = raw;

  if (filterIp.value.trim()) {
    const q = filterIp.value.trim();
    arr = arr.filter((r) => r.ip.includes(q));
  }

  arr.sort((a, b) => b.packets - a.packets);
  return arr.slice(0, 20);
});

// Scans / DoS
const scanEntries = computed<ScanEntry[]>(() => {
  if (!parsed.value) return [];
  return detectScansAndDos(parsed.value);
});

const filteredScans = computed<ScanEntry[]>(() => {
  let arr = scanEntries.value;
  if (filterIp.value.trim()) {
    const q = filterIp.value.trim();
    arr = arr.filter((s) => s.ip.includes(q));
  }
  if (showOnlySuspicious.value) {
    arr = arr.filter((s) => s.reasons.length >= 2);
  }
  return arr;
});

// SIP
const sipStats = computed<SipStats>(() => {
  if (!parsed.value) {
    return {
      totalPackets: 0,
      totalBytes: 0,
      topSources: [],
      topDests: [],
    };
  }
  return computeSipStats(parsed.value);
});

// Cameras
const cameras = computed<CameraEntry[]>(() => {
  if (!parsed.value) return [];
  return detectCameras(parsed.value);
});

// MITRE & storyline
const mitreHints = computed<AttackHint[]>(() => {
  if (!parsed.value) return [];
  return buildMitreHints(scanEntries.value, sipStats.value, cameras.value);
});

const storyline = computed<StoryItem[]>(() => {
  if (!parsed.value) return [];
  return buildStoryline(
    parsed.value,
    scanEntries.value,
    sipStats.value,
    cameras.value
  );
});

// timeline chart
function destroyTimelineChart() {
  if (timelineChart.value) {
    timelineChart.value.destroy();
    timelineChart.value = null;
  }
}

function updateTimelineChart() {
  destroyTimelineChart();
  if (!parsed.value || !timelineCanvas.value) return;

  const data = buildTimeline(parsed.value);
  if (!data.length) return;

  const labels = data.map((d) =>
    new Date(d.tsSec * 1000).toLocaleTimeString()
  );
  const counts = data.map((d) => d.count);

  timelineChart.value = new Chart(timelineCanvas.value, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "pps",
          data: counts,
          borderColor: "#42b883",
          backgroundColor: "rgba(66,184,131,0.15)",
          fill: true,
          tension: 0.2,
          pointRadius: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: "#e5e9f0" },
        },
      },
      scales: {
        x: {
          ticks: { color: "#a0a4b3" },
          grid: { color: "rgba(255,255,255,0.05)" },
        },
        y: {
          ticks: { color: "#a0a4b3" },
          grid: { color: "rgba(255,255,255,0.05)" },
        },
      },
    },
  });
}

watch(parsed, () => {
  setTimeout(updateTimelineChart, 0);
});

onMounted(() => {
  if (parsed.value) updateTimelineChart();
});

onBeforeUnmount(() => {
  destroyTimelineChart();
  // на всякий случай уберём класс, если останется
  document.body.classList.remove("no-scroll");
});

function formatTime(tsSec: number): string {
  if (!tsSec) return "—";
  return new Date(tsSec * 1000).toLocaleTimeString();
}

function openIpDetails(ip: string) {
  selectedIp.value = ip;
  document.body.classList.add("no-scroll");
}

function closeIpPanel() {
  selectedIp.value = null;
  document.body.classList.remove("no-scroll");
}

// ===== IP packets list for selected IP (for side panel) =====

const MAX_IP_PACKETS = 2000;

const selectedIpPackets = computed(() => {
  if (!parsed.value || !selectedIp.value) return [];
  const ip = selectedIp.value;
  const frames = parsed.value.frames.filter(
    (f) => f.srcIp === ip || f.dstIp === ip
  );
  return frames.slice(0, MAX_IP_PACKETS);
});

function tcpFlagsToString(flags?: number): string {
  if (flags == null) return "";
  const parts: string[] = [];
  if (flags & 0x02) parts.push("SYN");
  if (flags & 0x10) parts.push("ACK");
  if (flags & 0x01) parts.push("FIN");
  if (flags & 0x04) parts.push("RST");
  if (flags & 0x08) parts.push("PSH");
  if (flags & 0x20) parts.push("URG");
  return parts.join(",");
}

// HTTP
async function handleExtractHttp() {
  if (!parsed.value) {
    httpError.value = t("noDataYet");
    return;
  }
  httpLoading.value = true;
  httpError.value = null;
  httpObjects.value = null;

  try {
    const objs = await extractHttpObjects();
    httpObjects.value = objs;
    if (!objs.length) {
      httpError.value =
        "No standalone HTTP objects found in single packets.";
    }
  } catch (e: any) {
    httpError.value = e?.message || "Failed to extract HTTP objects";
  } finally {
    httpLoading.value = false;
  }
}

function downloadHttpObject(obj: HttpObject) {
  const blob = new Blob([obj.data], {
    type: obj.mime || "application/octet-stream",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = obj.filename || `http-object-${obj.id}.bin`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <div class="app-root">
    <header class="app-header">
      <div>
        <h1>{{ t("appTitle") }}</h1>
        <p>{{ t("appSubtitle") }}</p>
      </div>
      <div class="lang-switcher">
        <span class="lang-label">{{ t("language") }}:</span>
        <button
          v-for="lang in ['en', 'ru', 'uz']"
          :key="lang"
          :class="['lang-btn', { active: currentLang === lang }]"
          @click="setLang(lang as any)"
        >
          {{ lang.toUpperCase() }}
        </button>
      </div>
    </header>

    <section class="card upload-card">
      <h2>{{ t("uploadTitle") }}</h2>
      <p class="muted">
        {{ t("uploadHint") }}
      </p>

      <div class="upload-row">
        <label class="file-button">
          <span>{{ t("chooseFile") }}</span>
          <input type="file" accept=".pcap,.pcapng" @change="onFileChange" />
        </label>

        <button class="primary" :disabled="loading" @click="analyze">
          {{ loading ? t("analyzing") : t("analyzeButton") }}
        </button>
      </div>

      <p v-if="selectedFile" class="file-name">
        {{ t("selectedFile") }}:
        <strong>{{ selectedFile.name }}</strong>
      </p>

      <p v-if="error" class="error-text">
        {{ error }}
      </p>
    </section>

    <section v-if="parsed" class="grid">
      <!-- Summary -->
      <div class="card">
        <h2>{{ t("summaryTitle") }}</h2>
        <div class="stats-grid">
          <div class="stat">
            <div class="label">{{ t("totalPackets") }}</div>
            <div class="value">
              {{ totalPackets.toLocaleString() }}
            </div>
          </div>
          <div class="stat">
            <div class="label">{{ t("totalBytes") }}</div>
            <div class="value">
              {{ formatBytes(totalBytes) }}
            </div>
          </div>
        </div>
      </div>

      <!-- Timeline -->
      <div class="card">
        <h2>{{ t("timelineTitle") }}</h2>
        <div class="chart-wrapper">
          <canvas ref="timelineCanvas"></canvas>
        </div>
      </div>

      <!-- Heavy talkers -->
      <div class="card wide">
        <div class="card-header-row">
          <h2>{{ t("heavyTalkersTitle") }}</h2>
          <div class="filters-row">
            <span class="filters-label">{{ t("filters") }}:</span>
            <input
              v-model="filterIp"
              type="text"
              :placeholder="t('filterByIp')"
            />
          </div>
        </div>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t("srcIp") }}</th>
                <th class="right">{{ t("packets") }}</th>
                <th class="right">{{ t("bytes") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in ipStats"
                :key="row.ip"
                @click="openIpDetails(row.ip)"
                class="clickable-row"
              >
                <td>{{ row.ip }}</td>
                <td class="right">
                  {{ row.packets.toLocaleString() }}
                </td>
                <td class="right">
                  {{ formatBytes(row.bytes) }}
                </td>
              </tr>
              <tr v-if="!ipStats.length">
                <td colspan="3" class="muted center">
                  {{ t("noDataYet") }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Scans / DoS -->
      <div class="card wide">
        <div class="card-header-row">
          <h2>{{ t("scansTitle") }}</h2>
          <label class="checkbox">
            <input type="checkbox" v-model="showOnlySuspicious" />
            {{ t("showOnlySuspicious") }}
          </label>
        </div>
        <p class="muted">
          {{ t("scansHint") }}
        </p>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t("srcIp") }}</th>
                <th class="right">{{ t("packets") }}</th>
                <th class="right">{{ t("bytes") }}</th>
                <th class="right">PPS</th>
                <th class="right">{{ t("colSyn") }}</th>
                <th class="right">{{ t("colUniquePorts") }}</th>
                <th class="right">{{ t("colUniqueTargets") }}</th>
                <th>Reasons</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="s in filteredScans"
                :key="s.ip"
                class="suspect clickable-row"
                @click="openIpDetails(s.ip)"
              >
                <td>{{ s.ip }}</td>
                <td class="right">
                  {{ s.packets.toLocaleString() }}
                </td>
                <td class="right">
                  {{ formatBytes(s.bytes) }}
                </td>
                <td class="right">
                  {{ s.pps.toFixed(1) }}
                </td>
                <td class="right">
                  {{ s.synCount }}
                </td>
                <td class="right">
                  {{ s.uniqueDstPorts }}
                </td>
                <td class="right">
                  {{ s.uniqueDstIps }}
                </td>
                <td>
                  <span
                    v-for="r in s.reasons"
                    :key="r"
                    class="reason-badge"
                  >
                    {{ t(r) }}
                  </span>
                </td>
              </tr>
              <tr v-if="!filteredScans.length">
                <td colspan="8" class="muted center">
                  {{ t("noDataYet") }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- SIP -->
      <div class="card wide">
        <h2>{{ t("sipTitle") }}</h2>
        <p class="muted">
          {{ t("sipHint") }}
        </p>

        <div class="stats-grid">
          <div class="stat">
            <div class="label">{{ t("sipTotalPackets") }}</div>
            <div class="value">
              {{ sipStats.totalPackets.toLocaleString() }}
              <div class="muted small">
                {{ formatBytes(sipStats.totalBytes) }}
              </div>
            </div>
          </div>
        </div>

        <h3 class="subheading">{{ t("sipTopSources") }}</h3>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t("srcIp") }}</th>
                <th class="right">{{ t("packets") }}</th>
                <th class="right">{{ t("bytes") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in sipStats.topSources" :key="'sip-s-' + s.ip">
                <td>{{ s.ip }}</td>
                <td class="right">
                  {{ s.packets.toLocaleString() }}
                </td>
                <td class="right">
                  {{ formatBytes(s.bytes) }}
                </td>
              </tr>
              <tr v-if="!sipStats.topSources.length">
                <td colspan="3" class="muted center">
                  {{ t("noDataYet") }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <h3 class="subheading">{{ t("sipTopDests") }}</h3>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Dst IP</th>
                <th class="right">{{ t("packets") }}</th>
                <th class="right">{{ t("bytes") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in sipStats.topDests" :key="'sip-d-' + d.ip">
                <td>{{ d.ip }}</td>
                <td class="right">
                  {{ d.packets.toLocaleString() }}
                </td>
                <td class="right">
                  {{ formatBytes(d.bytes) }}
                </td>
              </tr>
              <tr v-if="!sipStats.topDests.length">
                <td colspan="3" class="muted center">
                  {{ t("noDataYet") }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Cameras -->
      <div class="card wide">
        <h2>{{ t("camerasTitle") }}</h2>
        <p class="muted">
          {{ t("camerasHint") }}
        </p>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t("srcIp") }}</th>
                <th class="right">{{ t("cameraScore") }}</th>
                <th>Reasons</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="c in cameras" :key="c.ip">
                <td>{{ c.ip }}</td>
                <td class="right">{{ c.score }}</td>
                <td>
                  <span
                    v-for="r in c.reasons"
                    :key="r"
                    class="reason-badge camera-reason"
                  >
                    {{ r }}
                  </span>
                </td>
              </tr>
              <tr v-if="!cameras.length">
                <td colspan="3" class="muted center">
                  {{ t("camerasNoCams") }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- HTTP Objects -->
      <div class="card wide">
        <div class="card-header-row">
          <h2>HTTP objects (single-packet responses)</h2>
          <button class="primary" :disabled="httpLoading" @click="handleExtractHttp">
            {{ httpLoading ? "Searching..." : "Extract HTTP files" }}
          </button>
        </div>

        <p class="muted small">
          Only HTTP responses fully contained in a single TCP packet are
          extracted (based on Content-Length). For bigger files split across
          multiple packets a full TCP reassembly engine would be required.
        </p>

        <p v-if="httpError" class="error-text">
          {{ httpError }}
        </p>

        <div
          v-if="httpObjects && httpObjects.length"
          class="table-wrapper"
        >
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>{{ t("time") }}</th>
                <th>Flow</th>
                <th>MIME</th>
                <th class="right">{{ t("bytes") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="obj in httpObjects" :key="obj.id">
                <td>{{ obj.id }}</td>
                <td>{{ formatTime(obj.tsSec) }}</td>
                <td>
                  {{ obj.srcIp }}:{{ obj.srcPort }} →
                  {{ obj.dstIp }}:{{ obj.dstPort }}
                </td>
                <td>{{ obj.mime }}</td>
                <td class="right">{{ formatBytes(obj.length) }}</td>
                <td class="right">
                  <button class="primary" @click="downloadHttpObject(obj)">
                    Download
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- MITRE -->
      <div v-if="mitreHints.length" class="card wide">
        <h2>{{ t("mitreTitle") }}</h2>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t("mitreColTechnique") }}</th>
                <th>{{ t("mitreColId") }}</th>
                <th>{{ t("mitreColSeverity") }}</th>
                <th>{{ t("mitreColReason") }}</th>
                <th>{{ t("mitreColIps") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(h, idx) in mitreHints" :key="'mt-' + idx">
                <td>{{ h.mitreId }}</td>
                <td>{{ h.mitreId }}</td>
                <td>
                  <span
                    class="severity-badge"
                    :class="'sev-' + h.severity"
                  >
                    {{ t(`mitre.severity.${h.severity}`) }}
                  </span>
                </td>
                <td>{{ t(h.reasonKey) }}</td>
                <td>
                  <code v-for="ip in h.ips" :key="ip" class="ip-chip">
                    {{ ip }}
                  </code>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Storyline -->
      <div v-if="storyline.length" class="card wide">
        <h2>{{ t("storylineTitle") }}</h2>
        <p class="muted">
          {{ t("storylineHint") }}
        </p>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t("time") }}</th>
                <th>{{ t("type") }}</th>
                <th>{{ t("srcIp") }}</th>
                <th>{{ t("comment") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(ev, idx) in storyline" :key="'st-' + idx">
                <td>{{ formatTime(ev.tsSec) }}</td>
                <td>
                  <span
                    class="severity-badge"
                    :class="[
                      'sev-mini',
                      ev.kind === 'dos'
                        ? 'sev-high'
                        : ev.kind === 'scan'
                        ? 'sev-medium'
                        : 'sev-low',
                    ]"
                  >
                    {{ ev.kind.toUpperCase() }}
                  </span>
                </td>
                <td>{{ ev.ip || "—" }}</td>
                <td>
                  {{
                    ev.kind === "scan"
                      ? t("story.scan")
                      : ev.kind === "dos"
                      ? t("story.dos")
                      : ev.kind === "sip"
                      ? t("story.sip")
                      : t("story.camera")
                  }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section v-else class="empty">
      <p>{{ t("noDataYet") }}</p>
    </section>

    <footer class="footer">
      <p class="muted small">
        {{ t("footerNote") }}
      </p>
    </footer>

    <!-- RIGHT SIDE IP PANEL -->
    <div
      v-if="selectedIp && ipDetailsMap[selectedIp]"
      class="ip-panel-backdrop"
      @click.self="closeIpPanel"
    >
      <aside class="ip-panel">
        <div class="ip-panel-header">
          <div>
            <div class="ip-panel-title">IP details</div>
            <div class="ip-panel-ip">{{ selectedIp }}</div>
          </div>
          <button class="ip-panel-close" @click="closeIpPanel">×</button>
        </div>

        <div class="ip-panel-body">
          <section class="ip-panel-section">
            <div class="stats-grid">
              <div class="stat">
                <div class="label">Outbound packets</div>
                <div class="value">
                  {{ ipDetailsMap[selectedIp].outboundPackets.toLocaleString() }}
                  <div class="muted small">
                    {{ formatBytes(ipDetailsMap[selectedIp].outboundBytes) }}
                  </div>
                </div>
              </div>
              <div class="stat">
                <div class="label">Inbound packets</div>
                <div class="value">
                  {{ ipDetailsMap[selectedIp].inboundPackets.toLocaleString() }}
                  <div class="muted small">
                    {{ formatBytes(ipDetailsMap[selectedIp].inboundBytes) }}
                  </div>
                </div>
              </div>
              <div class="stat">
                <div class="label">PPS (outbound)</div>
                <div class="value">
                  {{ ipDetailsMap[selectedIp].pps.toFixed(1) }}
                </div>
              </div>
              <div class="stat">
                <div class="label">Time range</div>
                <div class="value">
                  {{ formatTime(ipDetailsMap[selectedIp].firstTs) }} –
                  {{ formatTime(ipDetailsMap[selectedIp].lastTs) }}
                </div>
              </div>
            </div>
          </section>

          <section class="ip-panel-section">
            <h3 class="subheading">Top peers</h3>
            <div class="table-wrapper table-wrapper-tight">
              <table>
                <thead>
                  <tr>
                    <th>IP</th>
                    <th class="right">{{ t("packets") }}</th>
                    <th class="right">{{ t("bytes") }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="peer in ipDetailsMap[selectedIp].topTalkedTo"
                    :key="peer.ip"
                    @click="openIpDetails(peer.ip)"
                    class="clickable-row"
                  >
                    <td>{{ peer.ip }}</td>
                    <td class="right">
                      {{ peer.packets.toLocaleString() }}
                    </td>
                    <td class="right">
                      {{ formatBytes(peer.bytes) }}
                    </td>
                  </tr>
                  <tr v-if="!ipDetailsMap[selectedIp].topTalkedTo.length">
                    <td colspan="3" class="muted center">
                      {{ t("noDataYet") }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section class="ip-panel-section">
            <h3 class="subheading">Top dst ports</h3>
            <div class="table-wrapper table-wrapper-tight">
              <table>
                <thead>
                  <tr>
                    <th>Port</th>
                    <th class="right">{{ t("packets") }}</th>
                    <th class="right">{{ t("bytes") }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="p in ipDetailsMap[selectedIp].topDstPorts"
                    :key="p.port"
                  >
                    <td>{{ p.port }}</td>
                    <td class="right">
                      {{ p.packets.toLocaleString() }}
                    </td>
                    <td class="right">
                      {{ formatBytes(p.bytes) }}
                    </td>
                  </tr>
                  <tr v-if="!ipDetailsMap[selectedIp].topDstPorts.length">
                    <td colspan="3" class="muted center">
                      {{ t("noDataYet") }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section class="ip-panel-section packets-section">
            <h3 class="subheading">Packets for this IP</h3>
            <p class="muted small">
              Showing first {{ selectedIpPackets.length }} packets (in + out).
            </p>
            <div class="table-wrapper table-wrapper-tight ip-packets-table">
              <table>
                <thead>
                  <tr>
                    <th>{{ t("time") }}</th>
                    <th>Dir</th>
                    <th>Proto</th>
                    <th>Flow</th>
                    <th class="right">Len</th>
                    <th class="right">Flags</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="(f, idx) in selectedIpPackets"
                    :key="idx"
                  >
                    <td>{{ formatTime(f.tsSec) }}</td>
                    <td>
                      <span
                        class="dir-badge"
                        :class="f.srcIp === selectedIp ? 'dir-out' : 'dir-in'"
                      >
                        {{ f.srcIp === selectedIp ? "OUT" : "IN" }}
                      </span>
                    </td>
                    <td>{{ f.proto }}</td>
                    <td>
                      {{ f.srcIp }}<span v-if="f.srcPort">:{{ f.srcPort }}</span>
                      →
                      {{ f.dstIp }}<span v-if="f.dstPort">:{{ f.dstPort }}</span>
                    </td>
                    <td class="right">
                      {{ f.length }}
                    </td>
                    <td class="right">
                      <span v-if="f.proto === 'TCP' && f.tcpFlags != null">
                        {{ tcpFlagsToString(f.tcpFlags) }}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </aside>
    </div>
  </div>
</template>

<style>
:root {
  color-scheme: dark;
}

body {
  margin: 0;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
    sans-serif;
  background: radial-gradient(circle at top left, #1f2933, #0b1018 40%, #05070b);
  color: #ffffff;
}

/* выключаем скролл, когда открыт сайдбар */
body.no-scroll {
  overflow: hidden;
}

.app-root {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px 16px 64px;
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 24px;
}

.app-header h1 {
  margin: 0 0 6px;
  font-size: 26px;
}

.app-header p {
  margin: 0;
  color: #c0c4cc;
  font-size: 14px;
}

.lang-switcher {
  display: flex;
  align-items: center;
  gap: 6px;
}

.lang-label {
  font-size: 12px;
  color: #a0a4b3;
}

.lang-btn {
  border-radius: 999px;
  border: 1px solid #3b4558;
  background: #1b222e;
  color: #e5e9f0;
  font-size: 12px;
  padding: 4px 10px;
  cursor: pointer;
}
.lang-btn.active {
  border-color: #42b883;
  background: rgba(66, 184, 131, 0.15);
  color: #ffffff;
}

/* Cards */
.card {
  background: #1c2332;
  border-radius: 12px;
  padding: 14px 16px 16px;
  margin-bottom: 16px;
  border: 1px solid #2b3445;
  box-shadow: 0 14px 30px rgba(0, 0, 0, 0.55);
}

.card h2 {
  margin: 0 0 8px;
  font-size: 18px;
}

.subheading {
  margin-top: 12px;
  margin-bottom: 6px;
  font-size: 14px;
  color: #e5e9f0;
}

.muted {
  color: #a0a4b3;
  font-size: 13px;
}

.small {
  font-size: 12px;
}

.error-text {
  margin-top: 8px;
  color: #ff7373;
  font-size: 13px;
}

/* Upload */
.upload-card {
  margin-bottom: 24px;
}

.upload-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  margin-top: 10px;
}

.file-button {
  position: relative;
  overflow: hidden;
  display: inline-flex;
  align-items: center;
  padding: 8px 16px;
  border-radius: 999px;
  background: #121827;
  border: 1px solid #374055;
  color: #e3e6f0;
  font-size: 14px;
  cursor: pointer;
}
.file-button input[type="file"] {
  position: absolute;
  inset: 0;
  opacity: 0;
  cursor: pointer;
}

button.primary {
  background: #42b883;
  color: #02120b;
  border: none;
  border-radius: 999px;
  padding: 8px 18px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
}
button.primary:disabled {
  opacity: 0.6;
  cursor: default;
}
button.primary:not(:disabled):hover {
  background: #3aa373;
}

.file-name {
  margin-top: 6px;
  font-size: 13px;
  color: #cfd3dd;
}

/* Layout */
.grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 16px;
}

@media (min-width: 900px) {
  .grid {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
}

.card.wide {
  grid-column: 1 / -1;
}

/* Stats */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
  margin-top: 6px;
}

.stat {
  background: #242c3c;
  border-radius: 10px;
  padding: 8px 10px;
  border: 1px solid #343f55;
}

.stat .label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #a6adbd;
  margin-bottom: 4px;
}

.stat .value {
  font-size: 17px;
  font-weight: 600;
}

/* Table */
.table-wrapper {
  margin-top: 6px;
  overflow-x: auto;
}

.table-wrapper-tight {
  margin-top: 4px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

th,
td {
  padding: 6px 6px;
  border-bottom: 1px solid #2f384a;
}

th {
  text-align: left;
  font-weight: 500;
  color: #aab2c3;
  font-size: 12px;
}

td {
  color: #e3e6f0;
}

.right {
  text-align: right;
}

.center {
  text-align: center;
}

/* Filters */
.card-header-row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: center;
}

.filters-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.filters-label {
  font-size: 11px;
  color: #9aa2b0;
}

.filters-row input {
  background: #121827;
  border-radius: 999px;
  border: 1px solid #384258;
  padding: 4px 10px;
  font-size: 12px;
  color: #e3e6f0;
}
.filters-row input::placeholder {
  color: #6f7685;
}

/* Chart */
.chart-wrapper {
  margin-top: 6px;
  height: 220px;
}

/* Scans */
.checkbox {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #c0c4cc;
}

.checkbox input[type="checkbox"] {
  accent-color: #42b883;
}

tr.suspect td {
  background: rgba(255, 99, 132, 0.08);
}
tr.suspect td:first-child {
  border-left: 2px solid rgba(255, 99, 132, 0.9);
}

/* Reason badges */
.reason-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  margin: 2px 4px 2px 0;
  border-radius: 999px;
  background: rgba(255, 99, 132, 0.12);
  border: 1px solid rgba(255, 99, 132, 0.55);
  font-size: 11px;
  color: #ffd6de;
}

.camera-reason {
  background: rgba(66, 184, 131, 0.12);
  border-color: rgba(66, 184, 131, 0.6);
  color: #c2ffe0;
}

/* MITRE */
.severity-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.sev-low {
  background: rgba(99, 209, 110, 0.12);
  color: #96f29e;
  border: 1px solid rgba(99, 209, 110, 0.5);
}
.sev-medium {
  background: rgba(255, 193, 7, 0.12);
  color: #ffe29a;
  border: 1px solid rgba(255, 193, 7, 0.6);
}
.sev-high {
  background: rgba(255, 99, 132, 0.16);
  color: #ffb3c3;
  border: 1px solid rgba(255, 99, 132, 0.7);
}
.sev-mini {
  font-size: 10px;
}

/* Storyline */
.ip-chip {
  display: inline-block;
  background: #151b29;
  border-radius: 999px;
  padding: 1px 6px;
  margin: 1px 3px 1px 0;
}

/* Empty */
.empty {
  margin-top: 40px;
  text-align: center;
  color: #a0a4b3;
  font-size: 14px;
}

/* Footer */
.footer {
  margin-top: 28px;
  text-align: center;
}

/* Clickable rows */
.clickable-row {
  cursor: pointer;
}
.clickable-row:hover td {
  background: rgba(66, 184, 131, 0.12);
}

/* Direction badges */
.dir-badge {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.06em;
}
.dir-out {
  background: rgba(66, 184, 131, 0.16);
  color: #c4ffe1;
  border: 1px solid rgba(66, 184, 131, 0.7);
}
.dir-in {
  background: rgba(59, 130, 246, 0.16);
  color: #c7ddff;
  border: 1px solid rgba(59, 130, 246, 0.7);
}

/* RIGHT SIDE IP PANEL */
.ip-panel-backdrop {
  position: fixed;
  inset: 0;
  background: radial-gradient(
    circle at left,
    rgba(15, 23, 42, 0.4),
    rgba(2, 6, 23, 0.8)
  );
  display: flex;
  justify-content: flex-end;
  pointer-events: auto;
  z-index: 40;
}

.ip-panel {
  width: 420px;
  max-width: 100%;
  height: 100%;
  background: #050816;
  border-left: 1px solid #2b3445;
  box-shadow: -16px 0 40px rgba(0, 0, 0, 0.8);
  display: flex;
  flex-direction: column;
  padding: 14px 14px 18px;
}

.ip-panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 8px;
  border-bottom: 1px solid #252c3b;
}

.ip-panel-title {
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #9da4b8;
}

.ip-panel-ip {
  font-size: 18px;
  font-weight: 600;
  margin-top: 4px;
}

.ip-panel-close {
  border: none;
  background: #111827;
  color: #e5e9f0;
  border-radius: 999px;
  width: 28px;
  height: 28px;
  font-size: 18px;
  line-height: 1;
  cursor: pointer;
}
.ip-panel-close:hover {
  background: #1f2937;
}

/* теперь body панели — флекс-колонка, нижний блок занимает всё свободное */
.ip-panel-body {
  margin-top: 10px;
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.ip-panel-section {
  margin-bottom: 0;
}

/* последний блок с пакетами тянется до низа */
.packets-section {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.ip-packets-table {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
}

/* Scrollbars для таблицы пакетов */
.ip-packets-table::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.ip-packets-table::-webkit-scrollbar-track {
  background: #020617;
}
.ip-packets-table::-webkit-scrollbar-thumb {
  background: #4b5563;
  border-radius: 999px;
}
</style>
