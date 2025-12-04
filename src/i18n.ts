export type Lang = "en" | "ru" | "uz";

type Dict = Record<string, string>;

const messages: Record<Lang, Dict> = {
  en: {
    appTitle: "Wireshark Viewer (Browser edition)",
    appSubtitle:
      "Offline pcap/pcapng analyzer in your browser, like CyberChef — no backend required.",
    uploadTitle: "Upload capture file",
    uploadHint:
      "Drop a .pcap or .pcapng file here, or choose from disk and the tool will parse it locally.",
    chooseFile: "Choose file",
    selectedFile: "Selected file",
    analyzeButton: "Analyze",
    analyzing: "Analyzing...",
    noFile: "Please select a .pcap or .pcapng file",
    summaryTitle: "Global summary",
    totalPackets: "Total packets",
    totalBytes: "Total bytes",
    heavyTalkersTitle: "Heavy talkers (top IPs)",
    srcIp: "Source IP",
    packets: "Packets",
    bytes: "Bytes",
    language: "Language",
    noDataYet: "Upload a capture to see the analysis.",
    timelineTitle: "Timeline (packets per second)",
    filters: "Filters",
    filterByIp: "Filter by IP...",
    footerNote:
      "All parsing is done locally in the browser. Your pcap never leaves your machine.",

    // Scans / DoS
    scansTitle: "Suspicious traffic (Scans / DoS-like behavior)",
    scansHint:
      "Heuristics based on packets-per-second, number of unique ports and SYN packets. Red rows are the noisiest sources.",
    showOnlySuspicious: "only highly suspicious",
    colSyn: "SYN packets",
    colUniquePorts: "Unique dst ports",
    colUniqueTargets: "Unique dst IPs",

    // Reasons
    "reason.HIGH_PPS": "High PPS",
    "reason.MANY_PORTS": "Many target ports",
    "reason.MANY_SYN": "Many SYNs",
    "reason.MANY_TARGETS": "Many target IPs",

    // SIP
    sipTitle: "SIP / VoIP traffic (ports 5060/5061)",
    sipHint:
      "SIP signaling may indicate VoIP gateways, softphones or brute-force attempts on PBX.",
    sipTotalPackets: "Total SIP packets",
    sipTopSources: "Top SIP sources",
    sipTopDests: "Top SIP destinations",

    // Cameras
    camerasTitle: "Detected IP cameras (heuristics)",
    camerasHint:
      "Hosts that talk on typical camera ports (RTSP 554/8554, DVR ports, etc.). This is heuristic only.",
    camerasNoCams: "No obvious camera-like hosts found.",
    cameraScore: "Score",

    // MITRE
    mitreTitle: "MITRE ATT&CK — inferred techniques",
    mitreColTechnique: "Technique",
    mitreColId: "MITRE ID",
    mitreColSeverity: "Severity",
    mitreColReason: "Reason",
    mitreColIps: "Related IPs",
    "mitre.severity.low": "low",
    "mitre.severity.medium": "medium",
    "mitre.severity.high": "high",
    "mitre.network_scan": "High port/host scanning activity",
    "mitre.dos": "High PPS / flood-like traffic",

    // Storyline
    storylineTitle: "Traffic storyline",
    storylineHint:
      "Human-friendly summarized events: scans, DoS-like spikes, SIP activity and camera-like hosts.",
    "story.scan": "Possible network scan from this IP.",
    "story.dos": "Possible DoS-like behavior (very high PPS / many targets).",
    "story.sip": "Noticeable SIP/VoIP signaling in the capture.",
    "story.camera": "Host looks like an IP camera or DVR.",

    time: "Time",
    type: "Type",
    comment: "Comment",
  },

  ru: {
    appTitle: "Wireshark Viewer (браузерная версия)",
    appSubtitle:
      "Оффлайн-анализатор pcap/pcapng прямо в браузере, как CyberChef — без бэкенда.",
    uploadTitle: "Загрузка файла захвата",
    uploadHint:
      "Перетащите сюда файл .pcap или .pcapng, либо выберите с диска — разбор будет локальным.",
    chooseFile: "Выбрать файл",
    selectedFile: "Выбран файл",
    analyzeButton: "Анализировать",
    analyzing: "Анализ...",
    noFile: "Пожалуйста, выберите файл .pcap или .pcapng",
    summaryTitle: "Общая сводка",
    totalPackets: "Всего пакетов",
    totalBytes: "Всего байт",
    heavyTalkersTitle: "Тяжёлые говорящие (топ IP)",
    srcIp: "Источник IP",
    packets: "Пакеты",
    bytes: "Байты",
    language: "Язык",
    noDataYet: "Загрузите файл захвата, чтобы увидеть аналитику.",
    timelineTitle: "Таймлайн (пакеты в секунду)",
    filters: "Фильтры",
    filterByIp: "Фильтр по IP...",
    footerNote:
      "Весь разбор происходит локально в браузере. Ваш pcap никуда не отправляется.",

    scansTitle: "Подозрительный трафик (сканы / DoS-подобное)",
    scansHint:
      "Эвристики по PPS, количеству уникальных портов и числу SYN-пакетов. Красные строки — самые шумные источники.",
    showOnlySuspicious: "только самые подозрительные",
    colSyn: "SYN пакеты",
    colUniquePorts: "Уник. порты",
    colUniqueTargets: "Уник. цели",

    "reason.HIGH_PPS": "Высокий PPS",
    "reason.MANY_PORTS": "Много портов",
    "reason.MANY_SYN": "Много SYN",
    "reason.MANY_TARGETS": "Много адресатов",

    sipTitle: "SIP / VoIP трафик (порты 5060/5061)",
    sipHint:
      "SIP-сигнализация может указывать на VoIP-шлюзы, софтфоны или brute force по АТС.",
    sipTotalPackets: "Всего SIP пакетов",
    sipTopSources: "Топ SIP источников",
    sipTopDests: "Топ SIP получателей",

    camerasTitle: "Предполагаемые IP-камеры (эвристика)",
    camerasHint:
      "Хосты, работающие по типичным камерным портам (RTSP 554/8554, DVR-порты и т.п.). Это только эвристика.",
    camerasNoCams: "Явных хостов, похожих на IP-камеры, не найдено.",
    cameraScore: "Счёт",

    mitreTitle: "MITRE ATT&CK — предполагаемые техники",
    mitreColTechnique: "Техника",
    mitreColId: "MITRE ID",
    mitreColSeverity: "Важность",
    mitreColReason: "Причина",
    mitreColIps: "Связанные IP",
    "mitre.severity.low": "низкая",
    "mitre.severity.medium": "средняя",
    "mitre.severity.high": "высокая",
    "mitre.network_scan": "Активное сканирование портов/хостов",
    "mitre.dos": "Похожий на DoS залив трафика / высокий PPS",

    storylineTitle: "Хронология событий (storyline)",
    storylineHint:
      "Человекопонятные события: сканы, DoS-подобные всплески, SIP-активность и хосты, похожие на камеры.",
    "story.scan": "Возможное сетевое сканирование с этого IP.",
    "story.dos":
      "Возможное DoS-подобное поведение (очень высокий PPS / много целей).",
    "story.sip": "В захвате есть заметная SIP/VoIP-сигнализация.",
    "story.camera": "Хост похож на IP-камеру или DVR.",

    time: "Время",
    type: "Тип",
    comment: "Комментарий",
  },

  uz: {
    appTitle: "Wireshark Viewer (brauzer talqini)",
    appSubtitle:
      "CyberChef kabi brauzer ichida ishlaydigan offline pcap/pcapng tahlilchi. Backend shart emas.",
    uploadTitle: "Capture faylni yuklash",
    uploadHint:
      ".pcap yoki .pcapng faylni shu yerga tashlang yoki diskdan tanlang — hamma narsa lokal tahlil qilinadi.",
    chooseFile: "Fayl tanlash",
    selectedFile: "Tanlangan fayl",
    analyzeButton: "Tahlil qilish",
    analyzing: "Tahlil qilinyapti...",
    noFile: "Iltimos, .pcap yoki .pcapng fayl tanlang",
    summaryTitle: "Umumiy statistika",
    totalPackets: "Jami paketlar",
    totalBytes: "Jami baytlar",
    heavyTalkersTitle: "Eng faol IP manzillar",
    srcIp: "Manba IP",
    packets: "Paketlar",
    bytes: "Baytlar",
    language: "Til",
    noDataYet: "Trafik tahlilini ko‘rish uchun capture fayl yuklang.",
    timelineTitle: "Vaqt bo‘yicha (sekundiga paketlar)",
    filters: "Filtrlar",
    filterByIp: "IP bo‘yicha filtr...",
    footerNote:
      "Barcha tahlil brauzer ichida lokal bajariladi. Sizning pcap hech qayerga yuborilmaydi.",

    scansTitle: "Shubhali trafik (scan / DoS-ga o‘xshash)",
    scansHint:
      "PPS, noyob portlar soni va SYN paketlari bo‘yicha evristika. Qizil qatorlar — eng shovqin manbalar.",
    showOnlySuspicious: "faqat eng shubhali",
    colSyn: "SYN paketlar",
    colUniquePorts: "Noyob portlar",
    colUniqueTargets: "Noyob manzillar",

    "reason.HIGH_PPS": "Yuqori PPS",
    "reason.MANY_PORTS": "Ko‘p portlar",
    "reason.MANY_SYN": "Ko‘p SYN",
    "reason.MANY_TARGETS": "Ko‘p manzillar",

    sipTitle: "SIP / VoIP trafik (5060/5061 portlar)",
    sipHint:
      "SIP signalizatsiyasi VoIP shlyuzlari, softphone yoki ATS-ga brute force bo‘lishi mumkin.",
    sipTotalPackets: "Jami SIP paketlar",
    sipTopSources: "Eng faol SIP manbalar",
    sipTopDests: "Eng faol SIP qabul qiluvchilar",

    camerasTitle: "Aniqlangan IP-kameralar (evristika)",
    camerasHint:
      "Odatdagi kamera portlari (RTSP 554/8554, DVR portlar va hokazo) bilan ishlayotgan xostlar. Bu faqat evristika.",
    camerasNoCams: "IP-kameraga o‘xshagan aniq xostlar topilmadi.",
    cameraScore: "Ball",

    mitreTitle: "MITRE ATT&CK — taxminiy texnikalar",
    mitreColTechnique: "Texnika",
    mitreColId: "MITRE ID",
    mitreColSeverity: "Daraja",
    mitreColReason: "Sabab",
    mitreColIps: "Tegishli IP manzillar",
    "mitre.severity.low": "past",
    "mitre.severity.medium": "o‘rta",
    "mitre.severity.high": "yuqori",
    "mitre.network_scan": "Port/hostlarni faol skan qilish",
    "mitre.dos": "DoS-ga o‘xshash yuqori PPS / trafik toshqini",

    storylineTitle: "Voqealar ketma-ketligi (storyline)",
    storylineHint:
      "Inson uchun tushunarli voqealar: scan, DoS-ga o‘xshash piklar, SIP faolligi va kameraga o‘xshagan xostlar.",
    "story.scan": "Bu IP manzildan tarmoqni skan qilish ehtimoli bor.",
    "story.dos":
      "DoS-ga o‘xshash xatti-harakat (juda yuqori PPS / ko‘p nishonlar).",
    "story.sip": "Capture ichida sezilarli SIP/VoIP signalizatsiya mavjud.",
    "story.camera": "Xost IP-kamera yoki DVR ga o‘xshaydi.",

    time: "Vaqt",
    type: "Turi",
    comment: "Izoh",
  },
};

export function createI18n(initial: Lang = "en") {
  let lang: Lang = initial;

  const setLang = (l: Lang) => {
    lang = l;
  };

  const t = (key: string): string => {
    return messages[lang][key] || messages["en"][key] || key;
  };

  const getLang = () => lang;

  const getMessages = () => messages;

  return { t, setLang, getLang, getMessages };
}
