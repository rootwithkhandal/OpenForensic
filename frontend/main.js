// --------------------------------------------------
// OpenForensic Disk Imager Frontend Controller
// Handles UI states, Tauri IPC, and log rendering
// --------------------------------------------------

// Destructure Tauri APIs from global window injection or fall back to browser simulation
let invoke, listen;

const getTauriInvoke = () => {
  if (typeof window !== 'undefined') {
    if (window.__TAURI__?.core?.invoke) return window.__TAURI__.core.invoke;
    if (window.__TAURI__?.tauri?.invoke) return window.__TAURI__.tauri.invoke;
    if (window.__TAURI__?.invoke) return window.__TAURI__.invoke;
    if (window.__TAURI_INTERNALS__?.invoke) return window.__TAURI_INTERNALS__.invoke;
  }
  return null;
};

const getTauriListen = () => {
  if (typeof window !== 'undefined') {
    if (window.__TAURI__?.event?.listen) return window.__TAURI__.event.listen;
    if (window.__TAURI__?.listen) return window.__TAURI__.listen;
  }
  return null;
};

if (typeof window !== 'undefined' && (window.__TAURI__ || window.__TAURI_INTERNALS__)) {
  invoke = async (cmd, args) => {
    const fn = getTauriInvoke();
    if (typeof fn === 'function') {
      return fn(cmd, args);
    }
    throw new Error(`Tauri IPC invoke function not found when executing command: ${cmd}`);
  };

  listen = async (event, callback) => {
    const fn = getTauriListen();
    if (typeof fn === 'function') {
      return fn(event, callback);
    }
    return () => {};
  };
} else {
  // Browser simulation mode fallback
  const mockListeners = {};

  listen = async (event, callback) => {
    if (!mockListeners[event]) mockListeners[event] = [];
    mockListeners[event].push(callback);
    return () => {
      mockListeners[event] = mockListeners[event].filter(cb => cb !== callback);
    };
  };

  const triggerMockEvent = (event, payload) => {
    if (mockListeners[event]) {
      mockListeners[event].forEach(cb => cb({ payload }));
    }
  };

  let mockInterval = null;

  invoke = async (cmd, args) => {
    console.log(`[MOCK IPC] Invoke command: ${cmd}`, args);

    if (cmd === 'get_admin_status') {
      return true;
    }

    if (cmd === 'scan_devices') {
      await new Promise(r => setTimeout(r, 500));
      return [
        {
          name: 'PhysicalDrive0',
          path: '\\\\.\\PhysicalDrive0',
          size: 1000204886016,
          model: 'Samsung SSD 980 PRO 1TB',
          serial: 'S6BCNJ0R123456',
          vendor: 'Samsung',
          device_type: 'SSD',
          is_mounted: false,
          mount_points: [],
          partitions: [
            { name: 'Partition 1 (System)', size: 524288000, fs_type: 'FAT32' },
            { name: 'Partition 2 (OS)', size: 950000000000, fs_type: 'NTFS' },
            { name: 'Partition 3 (Recovery)', size: 49767086016, fs_type: 'NTFS (Hidden)' }
          ]
        },
        {
          name: 'PhysicalDrive1',
          path: '\\\\.\\PhysicalDrive1',
          size: 32017047552,
          model: 'Crucial USB Flash Drive',
          serial: '070324888123',
          vendor: 'Crucial',
          device_type: 'USB',
          is_mounted: false,
          mount_points: [],
          partitions: [
            { name: 'Partition 1 (USB Storage)', size: 32015000000, fs_type: 'exFAT' }
          ]
        }
      ];
    }

    if (cmd === 'browse_folder') {
      return 'C:\\Forensics\\Evidence_Source';
    }

    if (cmd === 'browse_file') {
      return args.ext === 'exe' || args.ext === 'vol' || args.ext === 'py' ? 'C:\\Forensics\\Tools\\custom_volatility.exe' : `C:\\Forensics\\Evidence\\sample.${args.ext || 'dd'}`;
    }

    if (cmd === 'save_file_dialog') {
      return `C:\\Forensics\\Acquisitions\\case_evidence.${args.ext || 'dd'}`;
    }

    if (cmd === 'check_checkpoint') {
      return false;
    }

    if (cmd === 'cancel_acquisition') {
      if (mockInterval) {
        clearInterval(mockInterval);
        triggerMockEvent('acquisition-event', { type: 'Log', data: '[SYSTEM] Acquisition cancelled by user.' });
        state.activeJob = false;
        toggleUIJobActive(false);
      }
      return;
    }

    if (cmd === 'start_triage') {
      const destPath = args.destPath;
      triggerMockEvent('acquisition-event', { type: 'Log', data: `[SYSTEM] Starting simulated rapid system triage to ${destPath}` });
      let progress = 0;
      mockInterval = setInterval(() => {
        progress += 25;
        if (progress === 25) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Gathering volatile process list and network sockets...' });
        } else if (progress === 50) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Dumping Windows registry system and SAM hives...' });
        } else if (progress === 75) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Extracting Chrome browser history databases...' });
        } else if (progress >= 100) {
          clearInterval(mockInterval);
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Packaging forensic triage files into destination...' });
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Rapid forensic triage completed successfully!' });
          triggerMockEvent('acquisition-event', {
            type: 'Finished',
            data: {
              bytes_read: 4096,
              bad_sectors: 0,
              hashes: { 'SHA-256': 'triage-tethered-integrity-sha256' }
            }
          });
        }
      }, 1000);
      return;
    }

    if (cmd === 'mount_image') {
      await new Promise(r => setTimeout(r, 800));
      return true;
    }

    if (cmd === 'start_acquisition') {
      const config = args.configInput;
      let bytes_read = 0;
      const total_size = config.imaging_mode === 'Physical' ? 32017047552 : 54000000;
      const speed = 125000000; // 125 MB/s
      let bad_sectors = 0;

      triggerMockEvent('acquisition-event', { type: 'Log', data: `[ACQUISITION] Starting simulated physical imaging of ${config.source_path}` });

      mockInterval = setInterval(() => {
        bytes_read += speed * 0.25;
        if (Math.random() < 0.02) {
          bad_sectors += 1;
          triggerMockEvent('acquisition-event', { type: 'Log', data: `[WARNING] Bad sector encountered at offset ${bytes_read} bytes` });
        }

        if (bytes_read >= total_size) {
          bytes_read = total_size;
          clearInterval(mockInterval);
          triggerMockEvent('acquisition-event', { type: 'Progress', data: { bytes_read, total_size, speed_bps: speed, bad_sectors } });
          triggerMockEvent('acquisition-event', {
            type: 'Finished',
            data: {
              bytes_read,
              bad_sectors,
              hashes: { 'MD5': '9e107d9d372bb6826bd81d3542a419d6', 'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
            }
          });
        } else {
          triggerMockEvent('acquisition-event', { type: 'Progress', data: { bytes_read, total_size, speed_bps: speed, bad_sectors } });
        }
      }, 250);
      return;
    }
    if (cmd === 'list_volumes') {
      await new Promise(r => setTimeout(r, 300));
      return [
        { letter: 'C:', label: 'Windows', fs_type: 'NTFS', total_size: 1000204886016, free_space: 450000000000 },
        { letter: 'D:', label: 'Data', fs_type: 'exFAT', total_size: 2000204886016, free_space: 1500000000000 }
      ];
    }

    if (cmd === 'start_live_acquisition') {
      const config = args.configInput;
      triggerMockEvent('acquisition-event', { type: 'Log', data: `[LIVE] Starting simulated live acquisition of volume ${config.volume} to ${config.dest_path}` });

      let progress = 0;
      mockInterval = setInterval(() => {
        progress += 20;
        if (progress === 20) {
          if (config.capture_ram) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Capturing physical memory (RAM)...' });
        } else if (progress === 40) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Creating VSS snapshot for consistent imaging...' });
        } else if (progress === 60) {
          if (config.capture_locked_files) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Copying OS-locked registry hives and MFT...' });
        } else if (progress === 80) {
          if (config.run_consistency_check) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Running filesystem consistency validation against VSS...' });
        } else if (progress >= 100) {
          clearInterval(mockInterval);
          if (config.auto_cleanup_vss) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Cleaning up temporary VSS snapshot...' });
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Live acquisition completed successfully! Reports generated.' });
          triggerMockEvent('acquisition-event', {
            type: 'Finished',
            data: {
              bytes_read: 0,
              bad_sectors: 0,
              hashes: {}
            }
          });
        }
      }, 1000);
      return;
    }
  };
}

// State management
let state = {
  imagingMode: 'Physical', // 'Physical' or 'Logical'
  acquisitionMode: 'Capture', // 'Capture' or 'Analysis'
  devices: [],
  selectedDeviceIndex: null,
  activeJob: false,
  logCount: 0
};

let currentTriageData = [];

function updateAnalysisLockScreens() {
  const isCapture = (state.acquisitionMode === 'Capture');
  
  // Timeline tab
  const lockTimeline = document.getElementById('lock-timeline');
  const contentTimeline = document.getElementById('content-timeline');
  if (lockTimeline && contentTimeline) {
    if (isCapture) {
      lockTimeline.classList.remove('hidden');
      contentTimeline.classList.add('hidden');
    } else {
      lockTimeline.classList.add('hidden');
      contentTimeline.classList.remove('hidden');
    }
  }

  // RAM tab
  const lockRam = document.getElementById('lock-ram');
  const contentRam = document.getElementById('content-ram');
  if (lockRam && contentRam) {
    if (isCapture) {
      lockRam.classList.remove('hidden');
      contentRam.classList.add('hidden');
    } else {
      lockRam.classList.add('hidden');
      contentRam.classList.remove('hidden');
    }
  }

  // RAM Viewer tab
  const lockRamViewer = document.getElementById('lock-ram-viewer');
  const contentRamViewer = document.getElementById('content-ram-viewer');
  if (lockRamViewer && contentRamViewer) {
    if (isCapture) {
      lockRamViewer.classList.remove('hidden');
      contentRamViewer.classList.add('hidden');
    } else {
      lockRamViewer.classList.add('hidden');
      contentRamViewer.classList.remove('hidden');
    }
  }

  // YARA tab
  const lockYara = document.getElementById('lock-yara');
  const contentYara = document.getElementById('content-yara');
  if (lockYara && contentYara) {
    if (isCapture) {
      lockYara.classList.remove('hidden');
      contentYara.classList.add('hidden');
    } else {
      lockYara.classList.add('hidden');
      contentYara.classList.remove('hidden');
    }
  }

  // Triage Workbench view
  const lockTriage = document.getElementById('lock-triage');
  const contentTriage = document.getElementById('content-triage');
  if (lockTriage && contentTriage) {
    if (isCapture) {
      lockTriage.classList.remove('hidden');
      contentTriage.classList.add('hidden');
    } else {
      lockTriage.classList.add('hidden');
      contentTriage.classList.remove('hidden');
    }
  }
}

function getImAppBadge(row) {
  const count = row.artifacts_count || 0;
  if (count > 0) {
    return `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-teal-500/20 text-teal-300 border border-teal-500/30">EVIDENCE COPIED (${count})</span>`;
  } else {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">INSTALLED (NO DATA)</span>';
  }
}

function getBrowserRiskBadge(row) {
  const count = row.history_count || 0;
  if (count > 0) {
    return `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-teal-500/20 text-teal-300 border border-teal-500/30">HISTORY EXTRACTED (${count})</span>`;
  } else {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">PROFILE ONLY / EMPTY</span>';
  }
}

function getAppRiskBadge(row) {
  const isSystem = row.is_system;
  const installer = (row.installer || '').toLowerCase();
  const pkg = (row.package_name || '').toLowerCase();
  
  if (!isSystem && installer && installer !== 'null' && installer !== 'com.android.vending' && installer !== 'com.google.android.feedback') {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">HIGH RISK: Side-loaded APK</span>';
  } else if (pkg.includes('whatsapp') || pkg.includes('telegram') || pkg.includes('signal') || pkg.includes('viber') || pkg.includes('wechat') || pkg.includes('messenger') || pkg.includes('tor') || pkg.includes('vpn')) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">MEDIUM: High-Interest App</span>';
  } else if (isSystem && (row.apk_path || '').startsWith('/data/')) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">HIGH RISK: System Anomaly</span>';
  } else {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-teal-500/20 text-teal-400 border border-teal-500/30">LOW RISK: Verified</span>';
  }
}

function getProcessRiskBadge(row) {
  const path = (row.exe_path || row.path || row.command_line || '').toLowerCase();
  if (path.includes('\\temp\\') || path.includes('/tmp/') || path.includes('\\appdata\\') || path.includes('\\programdata\\') || path.includes('/var/tmp/')) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">ANOMALY: Suspicious Path</span>';
  } else if (path.includes('powershell') || path.includes('cmd.exe') || path.includes('wscript') || path.includes('cscript') || path.includes('bash') || path.includes('sh')) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">MONITOR: Shell / Engine</span>';
  } else {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-teal-500/20 text-teal-400 border border-teal-500/30">NORMAL</span>';
  }
}

function getExecutionRiskBadge(row) {
  const exe = (row.executable_name || row.file_path || '').toLowerCase();
  const count = row.run_count !== undefined ? Number(row.run_count) : -1;
  const pub = (row.publisher || '').toLowerCase();

  if (exe.includes('\\temp\\') || exe.includes('\\appdata\\') || exe.includes('\\programdata\\') || exe.includes('/tmp/')) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">HIGH RISK: Temp/User Execution</span>';
  } else if (exe.includes('cmd.exe') || exe.includes('powershell') || exe.includes('certutil') || exe.includes('bitsadmin') || exe.includes('whoami') || exe.includes('mimikatz') || exe.includes('psexec') || exe.includes('net.exe')) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">ALERT: Suspicious Tool</span>';
  } else if (count === 1) {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">ANOMALY: Single Execution</span>';
  } else if (pub === 'unknown' || pub === 'unverified') {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">UNVERIFIED: Unsigned Publisher</span>';
  } else {
    return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-teal-500/20 text-teal-400 border border-teal-500/30">NORMAL</span>';
  }
}

// UI Elements Binding
const elements = {
  adminBadge: document.getElementById('admin-badge'),
  clockDisplay: document.getElementById('clock-display'),
  btnThemeToggle: document.getElementById('btn-theme-toggle'),
  btnRescan: document.getElementById('btn-rescan'),
  modePhysical: document.getElementById('mode-physical'),
  modeLogical: document.getElementById('mode-logical'),
  modeImage: document.getElementById('mode-image'),
  physicalContainer: document.getElementById('physical-container'),
  logicalContainer: document.getElementById('logical-container'),
  imageMountContainer: document.getElementById('image-mount-container'),
  mountImagePath: document.getElementById('mount-image-path'),
  btnBrowseMountImage: document.getElementById('btn-browse-mount-image'),
  mountReadOnly: document.getElementById('mount-read-only'),
  mountCustomPoint: document.getElementById('mount-custom-point'),
  btnMountAction: document.getElementById('btn-mount-action'),
  btnUnmountAction: document.getElementById('btn-unmount-action'),
  btnRefreshMounts: document.getElementById('btn-refresh-mounts'),
  mountedImagesBody: document.getElementById('mounted-images-body'),
  deviceList: document.getElementById('device-list'),

  logicalSourceInput: document.getElementById('logical-source-input'),
  btnBrowseSource: document.getElementById('btn-browse-source'),

  inputEvidenceId: document.getElementById('input-evidence-id'),
  inputCaseNumber: document.getElementById('input-case-number'),
  inputExaminer: document.getElementById('input-examiner'),
  inputNotes: document.getElementById('input-notes'),
  selectFormat: document.getElementById('select-format'),
  inputDestPath: document.getElementById('input-dest-path'),
  btnBrowseDest: document.getElementById('btn-browse-dest'),
  selectVerification: document.getElementById('select-verification'),
  selectBlocksize: document.getElementById('select-blocksize'),
  selectCompression: document.getElementById('select-compression'),
  selectSplit: document.getElementById('select-split'),
  customSplitGroup: document.getElementById('custom-split-group'),
  inputSplitSize: document.getElementById('input-split-size'),
  checkReadVerification: document.getElementById('check-read-verification'),
  inputKeywords: document.getElementById('input-keywords'),
  inputYaraPath: document.getElementById('input-yara-path'),
  btnBrowseYara: document.getElementById('btn-browse-yara'),
  checkSparse: document.getElementById('check-sparse'),
  checkDigitalSignature: document.getElementById('check-digital-signature'),

  hashMd5: document.getElementById('hash-md5'),
  hashSha1: document.getElementById('hash-sha1'),
  hashSha256: document.getElementById('hash-sha256'),
  hashSha512: document.getElementById('hash-sha512'),

  consoleLogs: document.getElementById('console-logs'),
  btnClearLog: document.getElementById('btn-clear-log'),
  btnExportLog: document.getElementById('btn-export-log'),
  btnModeToggle: document.getElementById('btn-mode-toggle'),

  monitorIdle: document.getElementById('monitor-idle'),
  monitorActive: document.getElementById('monitor-active'),
  idleStatusText: document.getElementById('idle-status-text'),
  btnStartAcquisition: document.getElementById('btn-start-acquisition'),
  btnResumeAcquisition: document.getElementById('btn-resume-acquisition'),
  btnCancelAcquisition: document.getElementById('btn-cancel-acquisition'),

  txtActiveJobDesc: document.getElementById('txt-active-job-desc'),
  txtStatSpeed: document.getElementById('txt-stat-speed'),
  txtStatEta: document.getElementById('txt-stat-eta'),
  txtStatBad: document.getElementById('txt-stat-bad'),
  txtStatPercent: document.getElementById('txt-stat-percent'),
  progressBarFill: document.getElementById('progress-bar-fill'),
  txtBytesProgress: document.getElementById('txt-bytes-progress'),

  // Triage Workbench
  triageModeLive: document.getElementById('triage-mode-live'),
  triageModeMounted: document.getElementById('triage-mode-mounted'),
  triageMountedContainer: document.getElementById('triage-mounted-container'),
  triageSourceRoot: document.getElementById('triage-source-root'),
  btnBrowseTriageSource: document.getElementById('btn-browse-triage-source'),
  triageDbPath: document.getElementById('triage-db-path'),
  btnBrowseTriageDb: document.getElementById('btn-browse-triage-db'),
  triageTableSelect: document.getElementById('triage-table-select'),
  btnLoadTriageTable: document.getElementById('btn-load-triage-table'),
  triageTableHead: document.getElementById('triage-table-head'),
  triageTableBody: document.getElementById('triage-table-body'),

  // Timeline
  timelineImagePath: document.getElementById('timeline-image-path'),
  btnBrowseTimelineImage: document.getElementById('btn-browse-timeline-image'),
  timelineDestPath: document.getElementById('timeline-dest-path'),
  btnBrowseTimelineDest: document.getElementById('btn-browse-timeline-dest'),
  btnStartTimeline: document.getElementById('btn-start-timeline'),

  // RAM Analysis
  ramImagePath: document.getElementById('ram-image-path'),
  btnBrowseRamImage: document.getElementById('btn-browse-ram-image'),
  ramVolPath: document.getElementById('ram-vol-path'),
  btnBrowseRamVol: document.getElementById('btn-browse-ram-vol'),
  ramProfileSelect: document.getElementById('ram-profile-select'),
  ramEnrichAbuseIp: document.getElementById('ram-enrich-abuseip'),
  ramEnrichVt: document.getElementById('ram-enrich-vt'),
  ramKeyAbuseIp: document.getElementById('ram-key-abuseip'),
  ramKeyVt: document.getElementById('ram-key-vt'),
  btnStartRamAnalysis: document.getElementById('btn-start-ram-analysis'),
  ramConsoleLogs: document.getElementById('ram-console-logs'),
  btnClearRamLog: document.getElementById('btn-clear-ram-log'),
  btnExportRamResults: document.getElementById('btn-export-ram-results'),

  // YARA Scanner
  yaraScanImagePath: document.getElementById('yara-scan-image-path'),
  btnBrowseYaraImage: document.getElementById('btn-browse-yara-image'),
  yaraScanRulesPath: document.getElementById('yara-scan-rules-path'),
  btnBrowseYaraRulesFile: document.getElementById('btn-browse-yara-rules-file'),
  btnBrowseYaraRulesDir: document.getElementById('btn-browse-yara-rules-dir'),
  btnStartYaraScan: document.getElementById('btn-start-yara-scan')
};

// Initialize Application
async function init() {
  logMessage('SYSTEM', 'OpenForensic Disk Imager UI loaded.');

  // 0. Initialize Theme
  initTheme();

  // 1. Start Clock Updater
  startClock();

  // 2. Fetch Admin privileges
  try {
    const adminPromise = invoke('get_admin_status');
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout retrieving admin status')), 5000));
    const isAdmin = await Promise.race([adminPromise, timeoutPromise]);
    updateAdminBadge(isAdmin);
  } catch (e) {
    logMessage('ERROR', 'Failed to retrieve privileges: ' + e);
    if (elements.adminBadge) {
      elements.adminBadge.className = 'badge badge-needs-admin';
      elements.adminBadge.textContent = 'Privilege Check Failed';
    }
  }

  // 3. Register Global Event Listeners
  setupEventListeners();

  // 4. Initial Scan of block devices
  await doRescan();
}

function initTheme() {
  const savedTheme = localStorage.getItem('OpenForensic-theme');
  if (savedTheme === 'light') {
    document.documentElement.classList.add('light-theme');
    elements.btnThemeToggle.textContent = '☾';
    elements.btnThemeToggle.title = 'Switch to Dark Mode';
  } else {
    document.documentElement.classList.remove('light-theme');
    elements.btnThemeToggle.textContent = '☀';
    elements.btnThemeToggle.title = 'Switch to Light Mode';
  }
}

function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light-theme');
  if (isLight) {
    localStorage.setItem('OpenForensic-theme', 'light');
    elements.btnThemeToggle.textContent = '☾';
    elements.btnThemeToggle.title = 'Switch to Dark Mode';
  } else {
    localStorage.setItem('OpenForensic-theme', 'dark');
    elements.btnThemeToggle.textContent = '☀';
    elements.btnThemeToggle.title = 'Switch to Light Mode';
  }
}

// Live Clock in IST
function startClock() {
  function update() {
    const now = new Date();
    // Offset by +5:30 for IST
    const istTime = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
    const istStr = istTime.toISOString().replace('T', ' ').substring(0, 19) + ' IST';
    elements.clockDisplay.textContent = istStr;
  }
  setInterval(update, 1000);
  update();
}

function updateAdminBadge(isAdmin) {
  elements.adminBadge.className = 'badge';
  if (isAdmin) {
    elements.adminBadge.textContent = 'Admin Mode';
    elements.adminBadge.classList.add('badge-admin');
    logMessage('SYSTEM', 'Running with elevated administrator privileges.');
  } else {
    elements.adminBadge.textContent = 'Needs Administrator Privileges';
    elements.adminBadge.classList.add('badge-needs-admin');
    logMessage('SYSTEM', 'WARNING: Running in standard user mode. Raw disk imaging will not be possible.');
  }
}

// Event Listeners
function setupEventListeners() {
  // Theme toggle button
  elements.btnThemeToggle.addEventListener('click', toggleTheme);

  // Mode selection buttons
  elements.modePhysical.addEventListener('click', () => setImagingMode('Physical'));
  elements.modeLogical.addEventListener('click', () => setImagingMode('Logical'));
  if (elements.modeImage) {
    elements.modeImage.addEventListener('click', () => setImagingMode('Image'));
  }
  if (elements.btnBrowseMountImage) {
    elements.btnBrowseMountImage.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: '' });
        if (file) {
          elements.mountImagePath.value = file;
          logMessage('SYSTEM', 'Selected disk image for mounting: ' + file);
        }
      } catch (e) {
        console.error('Failed to browse disk image:', e);
      }
    });
  }
  if (elements.btnMountAction) {
    elements.btnMountAction.addEventListener('click', mountDiskImage);
  }
  if (elements.btnUnmountAction) {
    elements.btnUnmountAction.addEventListener('click', unmountDiskImage);
  }
  if (elements.btnRefreshMounts) {
    elements.btnRefreshMounts.addEventListener('click', refreshMountedImages);
  }

  // Triage Source Mode toggle
  if (elements.triageModeLive && elements.triageModeMounted) {
    elements.triageModeLive.addEventListener('click', () => {
      elements.triageModeLive.classList.add('bg-primary', 'text-on-primary', 'shadow-sm');
      elements.triageModeLive.classList.remove('border', 'border-outline-variant', 'bg-surface', 'text-on-surface');
      elements.triageModeMounted.classList.remove('bg-primary', 'text-on-primary', 'shadow-sm');
      elements.triageModeMounted.classList.add('border', 'border-outline-variant', 'bg-surface', 'text-on-surface');
      elements.triageMountedContainer.classList.add('hidden');
      if (elements.triageSourceRoot) elements.triageSourceRoot.value = '';
    });
    elements.triageModeMounted.addEventListener('click', () => {
      elements.triageModeMounted.classList.add('bg-primary', 'text-on-primary', 'shadow-sm');
      elements.triageModeMounted.classList.remove('border', 'border-outline-variant', 'bg-surface', 'text-on-surface');
      elements.triageModeLive.classList.remove('bg-primary', 'text-on-primary', 'shadow-sm');
      elements.triageModeLive.classList.add('border', 'border-outline-variant', 'bg-surface', 'text-on-surface');
      elements.triageMountedContainer.classList.remove('hidden');
    });
  }
  if (elements.btnBrowseTriageSource) {
    elements.btnBrowseTriageSource.addEventListener('click', async () => {
      try {
        const folder = await invoke('browse_folder');
        if (folder && elements.triageSourceRoot) {
          elements.triageSourceRoot.value = folder;
          logMessage('SYSTEM', 'Selected triage target root: ' + folder);
        }
      } catch (e) {
        console.error('Failed to browse triage target root:', e);
      }
    });
  }

  // Rescan button
  elements.btnRescan.addEventListener('click', doRescan);

  // Browse source directory (Logical mode)
  elements.btnBrowseSource.addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_folder');
      if (folder) {
        elements.logicalSourceInput.value = folder;
        logMessage('SYSTEM', 'Selected source folder: ' + folder);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse folder: ' + e);
    }
  });

  // Browse destination path
  elements.btnBrowseDest.addEventListener('click', async () => {
    try {
      const format = elements.selectFormat.value;
      let ext = 'dd';
      if (format.includes('E01')) ext = 'e01';
      else if (format.includes('EX01')) ext = 'ex01';
      else if (format.includes('AFF')) ext = 'aff';
      else if (format.includes('SMART')) ext = 'smart';

      const file = await invoke('save_file_dialog', { ext });
      if (file) {
        elements.inputDestPath.value = file;
        logMessage('SYSTEM', 'Set destination file path: ' + file);
        // Check for checkpoints
        checkCheckpointExists(file);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to save file dialog: ' + e);
    }
  });

  // YARA Rules folder browse
  elements.btnBrowseYara.addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_yara_folder');
      if (folder) {
        elements.inputYaraPath.value = folder;
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse for YARA folder: ' + e);
    }
  });

  // Output format change updates file extensions if already populated
  elements.selectFormat.addEventListener('change', () => {
    const path = elements.inputDestPath.value;
    if (path) {
      const format = elements.selectFormat.value;
      let ext = '.dd';
      if (format.includes('E01')) ext = '.e01';
      else if (format.includes('EX01')) ext = '.ex01';
      else if (format.includes('AFF')) ext = '.aff';
      else if (format.includes('SMART')) ext = '.smart';

      // Replace old extension
      let cleanPath = path;
      if (path.endsWith('.dd') || path.endsWith('.e01') || path.endsWith('.ex01') || path.endsWith('.aff') || path.endsWith('.smart')) {
        cleanPath = path.substring(0, path.lastIndexOf('.'));
      }
      const newPath = cleanPath + ext;
      elements.inputDestPath.value = newPath;
      checkCheckpointExists(newPath);
    }
  });

  // Toggle custom splitting size display
  elements.selectSplit.addEventListener('change', () => {
    if (elements.selectSplit.value === 'Custom') {
      elements.customSplitGroup.classList.remove('hidden');
    } else {
      elements.customSplitGroup.classList.add('hidden');
    }
  });

  // Clear log console
  elements.btnClearLog.addEventListener('click', () => {
    elements.consoleLogs.innerHTML = '';
  });

  // Export log console
  elements.btnExportLog.addEventListener('click', () => {
    const logs = Array.from(elements.consoleLogs.children).map(c => c.textContent).join('\n');
    if (!logs) {
      alert('The console log is empty.');
      return;
    }
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `OpenForensic_console_log_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    logMessage('SYSTEM', 'Console log exported successfully.');
  });

  // Clear RAM log console
  if (elements.btnClearRamLog) {
    elements.btnClearRamLog.addEventListener('click', () => {
      if (elements.ramConsoleLogs) elements.ramConsoleLogs.innerHTML = '';
    });
  }

  // Export RAM analysis results
  if (elements.btnExportRamResults) {
    elements.btnExportRamResults.addEventListener('click', async () => {
      const imagePath = elements.ramImagePath?.value || '';
      try {
        let dbFiles = await invoke('list_ram_databases', { dirPath: imagePath || null });
        if (!dbFiles || dbFiles.length === 0) {
          if (!elements.ramConsoleLogs || elements.ramConsoleLogs.children[0]?.classList.contains('italic')) {
            alert('No RAM analysis results or JSON database found to export.');
            return;
          }
          const logs = Array.from(elements.ramConsoleLogs.children).map(c => c.textContent).join('\n');
          const blob = new Blob([logs], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `OpenForensic_RAM_Analysis_Logs_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          return;
        }
        let targetFile = dbFiles[dbFiles.length - 1];
        if (imagePath) {
          const match = dbFiles.find(f => f.replace(/\\/g, '/').toLowerCase().includes(imagePath.split(/[/\\]/).pop().split('.')[0].toLowerCase()));
          if (match) targetFile = match;
        }
        const jsonContent = await invoke('read_ram_database', { filePath: targetFile });
        const blob = new Blob([jsonContent], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = targetFile.split(/[/\\]/).pop() || `ram_forensic_results_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        logMessage('SYSTEM', `RAM Forensic JSON database exported: ${a.download}`);
        logRamMessage('SYSTEM', `RAM Forensic JSON database exported: ${a.download}`);
      } catch (err) {
        logMessage('ERROR', 'Failed to export RAM database: ' + err);
        alert('Failed to export JSON database: ' + err);
      }
    });
  }

  // Start Acquisition
  elements.btnStartAcquisition.addEventListener('click', (e) => {
    e.preventDefault();
    handleStartAcquisition(false);
  });

  // Resume Acquisition
  elements.btnResumeAcquisition.addEventListener('click', (e) => {
    e.preventDefault();
    handleStartAcquisition(true);
  });

  // Cancel Acquisition
  elements.btnCancelAcquisition.addEventListener('click', async () => {
    try {
      logMessage('SYSTEM', 'Cancelling active acquisition job...');
      await invoke('cancel_acquisition');
    } catch (e) {
      logMessage('ERROR', 'Event system setup failed: ' + e);
    }
  });

  // Tab Navigation Buttons
  document.getElementById('btn-tab-imaging').addEventListener('click', () => switchTab('imaging'));
  document.getElementById('btn-tab-triage').addEventListener('click', () => switchTab('triage'));
  document.getElementById('btn-tab-live').addEventListener('click', () => switchTab('live'));
  document.getElementById('btn-tab-timeline').addEventListener('click', () => switchTab('timeline'));
  document.getElementById('btn-tab-cases').addEventListener('click', () => { switchTab('cases'); loadCases(); });
  document.getElementById('btn-tab-ram').addEventListener('click', () => switchTab('ram'));
  document.getElementById('btn-tab-ram-viewer')?.addEventListener('click', () => { switchTab('ram-viewer'); refreshRamDbList(); });
  document.getElementById('btn-tab-yara')?.addEventListener('click', () => switchTab('yara'));
  document.getElementById('btn-tab-pgp').addEventListener('click', () => { switchTab('pgp'); loadPgpKeyInfo(); });

  document.getElementById('btn-refresh-cases').addEventListener('click', loadCases);

  // Triage Sub-Tabs & Unlock Buttons
  const btnSubTriageColl = document.getElementById('btn-subtab-triage-collection');
  const btnSubTriageWork = document.getElementById('btn-subtab-triage-workbench');
  const viewTriageColl = document.getElementById('triage-collection-view');
  const viewTriageWork = document.getElementById('triage-workbench-view');

  if (btnSubTriageColl && btnSubTriageWork && viewTriageColl && viewTriageWork) {
    btnSubTriageColl.addEventListener('click', () => {
      btnSubTriageColl.classList.add('active', 'bg-primary', 'text-on-primary', 'shadow-sm');
      btnSubTriageColl.classList.remove('bg-surface', 'border', 'border-outline-variant', 'text-on-surface');
      btnSubTriageWork.classList.remove('active', 'bg-primary', 'text-on-primary', 'shadow-sm');
      btnSubTriageWork.classList.add('bg-surface', 'border', 'border-outline-variant', 'text-on-surface');
      viewTriageColl.classList.remove('hidden');
      viewTriageWork.classList.add('hidden');
    });
    btnSubTriageWork.addEventListener('click', () => {
      btnSubTriageWork.classList.add('active', 'bg-primary', 'text-on-primary', 'shadow-sm');
      btnSubTriageWork.classList.remove('bg-surface', 'border', 'border-outline-variant', 'text-on-surface');
      btnSubTriageColl.classList.remove('active', 'bg-primary', 'text-on-primary', 'shadow-sm');
      btnSubTriageColl.classList.add('bg-surface', 'border', 'border-outline-variant', 'text-on-surface');
      viewTriageWork.classList.remove('hidden');
      viewTriageColl.classList.add('hidden');
      updateAnalysisLockScreens();
    });
  }

  document.querySelectorAll('.btn-unlock-analysis').forEach(btn => {
    btn.addEventListener('click', () => {
      if (elements.btnModeToggle) elements.btnModeToggle.click();
    });
  });

  // Acquisition Mode Toggle
  if (elements.btnModeToggle) {
    elements.btnModeToggle.addEventListener('click', async () => {
      if (state.acquisitionMode === 'Capture') {
        const confirmSwitch = confirm("Switching to Analysis Mode disables further evidence-modifying safeguards for this session.\n\nDo you wish to proceed?");
        if (confirmSwitch) {
          try {
            const investigator = elements.inputExaminer ? elements.inputExaminer.value : "Investigator";
            const caseId = elements.inputCaseNumber ? elements.inputCaseNumber.value : "N/A";
            await invoke('set_acquisition_mode', { mode: 'Analysis', investigator: investigator || "Investigator", caseId: caseId || "N/A" });
            state.acquisitionMode = 'Analysis';
            const displaySpan = document.getElementById('mode-display-text');
            if (displaySpan) displaySpan.textContent = "Mode: ANALYSIS";
            elements.btnModeToggle.classList.remove('bg-surface-container-high', 'text-on-surface');
            elements.btnModeToggle.classList.add('bg-amber-500', 'text-white');
            updateAnalysisLockScreens();
            logMessage('WARNING', 'Switched session acquisition mode to ANALYSIS. Evidence-modifying safeguards disabled.');
          } catch (e) {
            alert("Failed to switch mode: " + e);
            logMessage('ERROR', 'Failed to set acquisition mode: ' + e);
          }
        }
      } else {
        const confirmSwitch = confirm("Switch back to Capture Mode? (Safeguards will be re-enabled)");
        if (confirmSwitch) {
          try {
            const investigator = elements.inputExaminer ? elements.inputExaminer.value : "Investigator";
            const caseId = elements.inputCaseNumber ? elements.inputCaseNumber.value : "N/A";
            await invoke('set_acquisition_mode', { mode: 'Capture', investigator: investigator || "Investigator", caseId: caseId || "N/A" });
            state.acquisitionMode = 'Capture';
            const displaySpan = document.getElementById('mode-display-text');
            if (displaySpan) displaySpan.textContent = "Mode: CAPTURE";
            elements.btnModeToggle.classList.remove('bg-amber-500', 'text-white');
            elements.btnModeToggle.classList.add('bg-surface-container-high', 'text-on-surface');
            updateAnalysisLockScreens();
            logMessage('SYSTEM', 'Switched session acquisition mode to CAPTURE.');
          } catch (e) {
            alert("Failed to switch mode: " + e);
            logMessage('ERROR', 'Failed to set acquisition mode: ' + e);
          }
        }
      }
    });
  }

  // Triage Destination folder browse
  document.getElementById('btn-browse-triage-dest').addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_folder');
      if (folder) {
        document.getElementById('triage-dest-path').value = folder;
        logMessage('SYSTEM', 'Set triage destination directory: ' + folder);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse folder: ' + e);
    }
  });

  // Triage Workbench Handlers
  if (elements.btnBrowseTriageDb) {
    elements.btnBrowseTriageDb.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'db' });
        if (file) {
          elements.triageDbPath.value = file;
          logMessage('SYSTEM', 'Loaded Triage DB: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse for Triage DB: ' + e);
      }
    });
  }

  if (elements.btnLoadTriageTable) {
    elements.btnLoadTriageTable.addEventListener('click', async () => {
      const dbPath = elements.triageDbPath.value;
      if (!dbPath) {
        alert("Please select a triage.db file first.");
        return;
      }
      const table = elements.triageTableSelect.value;
      elements.triageTableBody.innerHTML = '<tr><td style="padding: 12px; color: var(--text-muted);">Querying database...</td></tr>';

      try {
        const resultJson = await invoke('query_triage_db', { dbPath, tableName: table });
        const data = JSON.parse(resultJson);
        renderTriageTable(data);
        logMessage('SYSTEM', `Loaded ${data.length} records from ${table}.`);
      } catch (e) {
        elements.triageTableBody.innerHTML = `<tr><td style="padding: 12px; color: #ff5555;">Error: ${e}</td></tr>`;
        logMessage('ERROR', 'Triage query failed: ' + e);
      }
    });
  }

  const btnCustomSql = document.getElementById('btn-execute-custom-sql');
  if (btnCustomSql) {
    btnCustomSql.addEventListener('click', async () => {
      const dbPath = elements.triageDbPath.value;
      if (!dbPath) {
        alert("Please select a triage database file first.");
        return;
      }
      const query = document.getElementById('triage-custom-sql')?.value || '';
      if (!query.trim()) {
        alert("Please enter a SQL query.");
        return;
      }
      elements.triageTableBody.innerHTML = '<tr><td class="p-8 text-center text-outline font-sans">Executing custom query...</td></tr>';
      try {
        const resultJson = await invoke('query_triage_db_custom', { dbPath, query });
        const data = JSON.parse(resultJson);
        renderTriageTable(data);
        logMessage('SYSTEM', `Executed custom SQL query: ${data.length} records returned.`);
      } catch (e) {
        elements.triageTableBody.innerHTML = `<tr><td class="p-8 text-center text-red-400 font-sans">Query Error: ${e}</td></tr>`;
        logMessage('ERROR', 'Custom SQL query failed: ' + e);
      }
    });
  }

  const filterInput = document.getElementById('triage-table-filter');
  if (filterInput) {
    filterInput.addEventListener('input', () => {
      const q = filterInput.value.toLowerCase().trim();
      if (!q) {
        renderFilteredTable(currentTriageData);
        return;
      }
      const filtered = currentTriageData.filter(row => {
        return Object.values(row).some(val => {
          if (val === null || val === undefined) return false;
          return String(val).toLowerCase().includes(q);
        });
      });
      renderFilteredTable(filtered);
    });
  }

  const btnExportCsv = document.getElementById('btn-export-triage-csv');
  if (btnExportCsv) {
    btnExportCsv.addEventListener('click', () => {
      if (!currentTriageData || currentTriageData.length === 0) {
        alert("No data to export.");
        return;
      }
      const keys = Object.keys(currentTriageData[0]);
      let csv = keys.join(',') + '\n';
      currentTriageData.forEach(row => {
        const values = keys.map(k => {
          let v = row[k] === null || row[k] === undefined ? '' : String(row[k]);
          v = v.replace(/"/g, '""');
          if (v.includes(',') || v.includes('\n') || v.includes('"')) {
            v = `"${v}"`;
          }
          return v;
        });
        csv += values.join(',') + '\n';
      });
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `triage_export_${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      logMessage('SYSTEM', 'Exported triage data to CSV.');
    });
  }

  const btnExportJson = document.getElementById('btn-export-triage-json');
  if (btnExportJson) {
    btnExportJson.addEventListener('click', () => {
      if (!currentTriageData || currentTriageData.length === 0) {
        alert("No data to export.");
        return;
      }
      const blob = new Blob([JSON.stringify(currentTriageData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `triage_export_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      logMessage('SYSTEM', 'Exported triage data to JSON.');
    });
  }

  // SIEM Helper
  function getSiemConfigFromUI() {
    const enabled = document.getElementById('triage-siem-enable')?.checked || false;
    const destTypeVal = document.getElementById('siem-type')?.value || 'splunk_hec';
    let destination_type = 'splunk_hec';
    if (destTypeVal === 'wazuh_socket') destination_type = 'wazuh_socket';
    if (destTypeVal === 'wazuh_local_log') destination_type = 'wazuh_local_log';

    return {
      destination_type,
      endpoint: document.getElementById('siem-endpoint')?.value || '',
      auth_token: document.getElementById('siem-token')?.value || '',
      index: document.getElementById('siem-index')?.value || 'openforensic_triage',
      enabled
    };
  }

  const btnTestSiem = document.getElementById('btn-test-siem');
  if (btnTestSiem) {
    btnTestSiem.addEventListener('click', async () => {
      try {
        logMessage('SYSTEM', 'Testing connection to SIEM endpoint...');
        btnTestSiem.disabled = true;
        const config = getSiemConfigFromUI();
        const res = await invoke('test_siem_connection', { config });
        logMessage('SUCCESS', '[SIEM] ' + res);
        alert('Connection Successful:\n' + res);
      } catch (err) {
        logMessage('ERROR', '[SIEM] Connection test failed: ' + err);
        alert('SIEM Connection Failed:\n' + err);
      } finally {
        btnTestSiem.disabled = false;
      }
    });
  }

  const btnSaveSiem = document.getElementById('btn-save-siem');
  if (btnSaveSiem) {
    btnSaveSiem.addEventListener('click', async () => {
      try {
        const config = getSiemConfigFromUI();
        await invoke('save_siem_config', { config });
        logMessage('SYSTEM', '[SIEM] Configuration saved to memory state.');
        alert('SIEM configuration saved successfully!');
      } catch (err) {
        logMessage('ERROR', '[SIEM] Failed to save config: ' + err);
      }
    });
  }

  const btnExportSiemNow = document.getElementById('btn-export-siem-now');
  if (btnExportSiemNow) {
    btnExportSiemNow.addEventListener('click', async () => {
      const dbPath = document.getElementById('triage-db-path')?.value;
      if (!dbPath) {
        alert('Please select or browse a triage.db file in the Triage Analysis Workbench first!');
        return;
      }
      try {
        logMessage('SYSTEM', `Starting manual SIEM export of ${dbPath}...`);
        btnExportSiemNow.disabled = true;
        const config = getSiemConfigFromUI();
        const summary = await invoke('export_triage_to_siem', { dbPath, config });
        logMessage('SUCCESS', `[SIEM] Export complete: ${summary.successful_events} events sent successfully, ${summary.failed_events} failed.`);
        alert(`SIEM Export Complete:\n${summary.message}`);
      } catch (err) {
        logMessage('ERROR', '[SIEM] Export error: ' + err);
        alert('SIEM Export Failed:\n' + err);
      } finally {
        btnExportSiemNow.disabled = false;
      }
    });
  }

  // Triage Start button click
  document.getElementById('btn-start-triage').addEventListener('click', async (e) => {
    e.preventDefault();
    const destPath = document.getElementById('triage-dest-path').value;
    if (!destPath) {
      alert('Please select a triage destination directory.');
      return;
    }
    const collect_registry = document.getElementById('triage-registry').checked;
    const collect_volatile = document.getElementById('triage-volatile').checked;
    const collect_browsers = document.getElementById('triage-browsers').checked;
    const collect_eventlogs = document.getElementById('triage-eventlogs').checked;
    const collect_im_apps = document.getElementById('triage-im-apps') ? document.getElementById('triage-im-apps').checked : true;
    const collect_memory = document.getElementById('triage-memory') ? document.getElementById('triage-memory').checked : true;
    const collect_network = document.getElementById('triage-network') ? document.getElementById('triage-network').checked : true;
    const collect_mobile = document.getElementById('triage-mobile') ? document.getElementById('triage-mobile').checked : false;
    const collect_cloud = document.getElementById('triage-cloud') ? document.getElementById('triage-cloud').checked : false;
    const collect_iot = document.getElementById('triage-iot') ? document.getElementById('triage-iot').checked : true;
    const triage_profile = document.getElementById('triage-profile-select') ? document.getElementById('triage-profile-select').value : null;
    const automation_level = document.getElementById('triage-automation-select') ? document.getElementById('triage-automation-select').value : null;
    const siemConfig = getSiemConfigFromUI();

    try {
      state.activeJob = true;
      toggleUIJobActive(true);
      resetStats();
      logMessage('SYSTEM', 'Initiating rapid triage collection...');

      const sourceRoot = elements.triageSourceRoot && !elements.triageMountedContainer?.classList.contains('hidden') ? (elements.triageSourceRoot.value.trim() || null) : null;
      await invoke('start_triage', {
        destPath,
        collectRegistry: collect_registry,
        collectVolatile: collect_volatile,
        collectBrowsers: collect_browsers,
        collectEventlogs: collect_eventlogs,
        collectImApps: collect_im_apps,
        collectMemory: collect_memory,
        collectNetwork: collect_network,
        collectMobile: collect_mobile,
        collectCloud: collect_cloud,
        collectIot: collect_iot,
        triageProfile: triage_profile,
        automationLevel: automation_level,
        siemConfig: siemConfig.enabled ? siemConfig : null,
        sourceRoot: sourceRoot
      });

      // Auto-load DB path for analysis workbench and populate summary box if it succeeds
      if (elements.triageDbPath) {
         const db = destPath + "\\triage.db";
         elements.triageDbPath.value = db;
         const statMap = [
           { table: 'processes', id: 'stat-processes' },
           { table: 'network_connections', id: 'stat-connections' },
           { table: 'browser_history', id: 'stat-history' },
           { table: 'installed_browsers', id: 'stat-browsers' },
           { table: 'event_logs', id: 'stat-logs' },
           { table: 'im_apps', id: 'stat-im-apps' },
           { table: 'memory_triage', id: 'stat-memory' },
           { table: 'network_triage', id: 'stat-network-triage' },
           { table: 'cloud_remote_triage', id: 'stat-cloud' },
           { table: 'iot_embedded_triage', id: 'stat-iot' },
           { table: 'triage_audit_log', id: 'stat-audit' }
         ];
         for (const item of statMap) {
           try {
             const resJson = await invoke('query_triage_db', { dbPath: db, tableName: item.table });
             const rows = JSON.parse(resJson);
             const el = document.getElementById(item.id);
             if (el) el.textContent = rows.length.toString();
           } catch (e) { /* table skipped or empty */ }
         }
      }
    } catch (err) {
      state.activeJob = false;
      toggleUIJobActive(false);
      logMessage('ERROR', 'Failed to start triage: ' + err);
      alert('Failed to start triage: ' + err);
    }
  });


  // Triage Workbench Renderer
  function renderTriageTable(data) {
    currentTriageData = data || [];
    renderFilteredTable(currentTriageData);
  }

  function renderFilteredTable(data) {
    const countEl = document.getElementById('triage-row-count');
    if (countEl) countEl.textContent = `${(data || []).length} rows loaded`;

    if (!data || data.length === 0) {
      elements.triageTableHead.innerHTML = '<th class="p-3">No Data</th>';
      elements.triageTableBody.innerHTML = '<tr><td class="p-8 text-center text-outline font-sans">No records found matching query or filter.</td></tr>';
      return;
    }

    const firstRow = data[0];
    const keys = Object.keys(firstRow);
    const hasBrowserRisk = ('browser_name' in firstRow && 'history_count' in firstRow);
    const hasImRisk = !hasBrowserRisk && ('app_name' in firstRow && 'artifacts_count' in firstRow);
    const hasAppRisk = !hasBrowserRisk && !hasImRisk && ('package_name' in firstRow);
    const hasProcRisk = ('pid' in firstRow || 'exe_path' in firstRow || 'command_line' in firstRow);
    const hasExecRisk = ('prefetch_hash' in firstRow || 'source_type' in firstRow);

    let theadHtml = '';
    if (hasBrowserRisk || hasImRisk || hasAppRisk || hasProcRisk || hasExecRisk) {
      theadHtml += '<th style="padding: 12px; font-weight: bold; color: var(--color-primary);">Status &amp; Evidence</th>';
    }
    keys.forEach(key => {
      theadHtml += `<th style="padding: 12px; font-weight: 600; text-transform: capitalize;">${key.replace(/_/g, ' ')}</th>`;
    });
    elements.triageTableHead.innerHTML = theadHtml;

    let tbodyHtml = '';
    data.forEach(row => {
      tbodyHtml += '<tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">';
      if (hasBrowserRisk) {
        tbodyHtml += `<td style="padding: 10px 12px;">${getBrowserRiskBadge(row)}</td>`;
      } else if (hasImRisk) {
        tbodyHtml += `<td style="padding: 10px 12px;">${getImAppBadge(row)}</td>`;
      } else if (hasAppRisk) {
        tbodyHtml += `<td style="padding: 10px 12px;">${getAppRiskBadge(row)}</td>`;
      } else if (hasProcRisk) {
        tbodyHtml += `<td style="padding: 10px 12px;">${getProcessRiskBadge(row)}</td>`;
      } else if (hasExecRisk) {
        tbodyHtml += `<td style="padding: 10px 12px;">${getExecutionRiskBadge(row)}</td>`;
      }
      keys.forEach(key => {
        let val = row[key];
        if (val === null || val === undefined) val = '';
        if (typeof val === 'string' && val.length > 200) val = val.substring(0, 200) + '...';
        tbodyHtml += `<td style="padding: 10px 12px; word-break: break-word;">${val}</td>`;
      });
      tbodyHtml += '</tr>';
    });
    elements.triageTableBody.innerHTML = tbodyHtml;
  }

  // Live Acquisition Buttons
  document.getElementById('btn-refresh-volumes').addEventListener('click', async () => {
    try {
      const select = document.getElementById('live-volume-select');
      select.innerHTML = '<option value="">Scanning...</option>';
      const vols = await invoke('list_volumes');
      select.innerHTML = vols.map(v => `<option value="${v.letter}">${v.letter} [${v.label}] - ${v.fs_type}</option>`).join('');
      if (vols.length === 0) select.innerHTML = '<option value="">No volumes found</option>';
      logMessage('SYSTEM', `Refreshed system volumes (${vols.length} found).`);
    } catch (e) {
      logMessage('ERROR', 'Failed to list volumes: ' + e);
    }
  });

  document.getElementById('btn-browse-live-dest').addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_folder');
      if (folder) {
        document.getElementById('live-dest-path').value = folder;
        logMessage('SYSTEM', 'Set live acquisition destination directory: ' + folder);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse folder: ' + e);
    }
  });

  document.getElementById('btn-browse-ram-tool').addEventListener('click', async () => {
    try {
      const file = await invoke('browse_file', { ext: 'vol' });
      if (file) {
        document.getElementById('live-ram-tool').value = file;
        logMessage('SYSTEM', 'Set custom RAM acquisition tool: ' + file);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse file: ' + e);
    }
  });

  document.getElementById('btn-start-live').addEventListener('click', async (e) => {
    e.preventDefault();
    const volume = document.getElementById('live-volume-select').value;
    const destPath = document.getElementById('live-dest-path').value;

    if (!volume || !destPath) {
      alert('Please select both a system volume and a destination folder.');
      return;
    }

    const config = {
      volume,
      dest_path: destPath,
      evidence_id: document.getElementById('live-evidence-id').value,
      notes: document.getElementById('live-notes').value,
      case_number: document.getElementById('live-case-num').value,
      examiner: document.getElementById('live-examiner').value,
      capture_ram: document.getElementById('live-cb-ram').checked,
      capture_locked_files: document.getElementById('live-cb-locked').checked,
      run_consistency_check: document.getElementById('live-cb-consistency').checked,
      image_vss: document.getElementById('live-cb-image-vss').checked,
      auto_cleanup_vss: document.getElementById('live-cb-cleanup').checked,
      ram_tool_path: document.getElementById('live-ram-tool').value || null,
      hash_algorithms: ['SHA256']
    };

    try {
      state.activeJob = true;
      toggleUIJobActive(true);
      resetStats();
      logMessage('SYSTEM', 'Initiating live system acquisition pipeline...');
      await invoke('start_live_acquisition', { configInput: config });
    } catch (err) {
      state.activeJob = false;
      toggleUIJobActive(false);
      logMessage('ERROR', 'Failed to start live acquisition: ' + err);
      alert('Failed to start live acquisition: ' + err);
    }
  });

  // Timeline Handlers
  if (elements.btnBrowseTimelineImage) {
    elements.btnBrowseTimelineImage.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'dd' });
        if (file) {
          elements.timelineImagePath.value = file;
          logMessage('SYSTEM', 'Selected image for timeline: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse image: ' + e);
      }
    });
  }

  if (elements.btnBrowseTimelineDest) {
    elements.btnBrowseTimelineDest.addEventListener('click', async () => {
      try {
        const folder = await invoke('browse_folder');
        if (folder) {
          elements.timelineDestPath.value = folder;
          logMessage('SYSTEM', 'Selected timeline destination: ' + folder);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse folder: ' + e);
      }
    });
  }

  if (elements.btnStartTimeline) {
    elements.btnStartTimeline.addEventListener('click', async (e) => {
      e.preventDefault();
      const imagePath = elements.timelineImagePath.value;
      const destPath = elements.timelineDestPath.value;

      if (!imagePath || !destPath) {
        alert('Please select both an image file and a destination directory.');
        return;
      }

      try {
        logMessage('SYSTEM', 'Starting timeline generation... This may take a while.');
        elements.btnStartTimeline.disabled = true;
        elements.btnStartTimeline.textContent = 'Generating...';

        const result = await invoke('generate_image_timeline', {
          imagePath: imagePath,
          outputDir: destPath
        });

        logMessage('SYSTEM', result);
        alert(result);
      } catch (err) {
        logMessage('ERROR', 'Failed to generate timeline: ' + err);
        alert('Failed to generate timeline: ' + err);
      } finally {
        elements.btnStartTimeline.disabled = false;
        elements.btnStartTimeline.textContent = '▶ Generate Timeline';
      }
    });
  }

  // RAM Analysis Handlers
  if (elements.btnBrowseRamImage) {
    elements.btnBrowseRamImage.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'raw' });
        if (file) {
          elements.ramImagePath.value = file;
          logMessage('SYSTEM', 'Selected memory dump for analysis: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse memory dump: ' + e);
      }
    });
  }

  if (elements.btnBrowseRamVol) {
    elements.btnBrowseRamVol.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'vol' });
        if (file) {
          elements.ramVolPath.value = file;
          logMessage('SYSTEM', 'Selected Volatility engine executable: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse Volatility executable: ' + e);
      }
    });
  }

  if (elements.btnStartRamAnalysis) {
    elements.btnStartRamAnalysis.addEventListener('click', async (e) => {
      e.preventDefault();
      const imagePath = elements.ramImagePath.value;
      const volPath = elements.ramVolPath.value;

      if (!imagePath) {
        alert('Please select a memory dump file to analyze.');
        return;
      }

      const config = {
        image_path: imagePath,
        vol_path: volPath,
        profile: elements.ramProfileSelect.value,
        enrich_vt: elements.ramEnrichVt ? elements.ramEnrichVt.checked : false,
        enrich_mb: false,
        enrich_abuseip: elements.ramEnrichAbuseIp ? elements.ramEnrichAbuseIp.checked : false,
        vt_key: elements.ramKeyVt ? elements.ramKeyVt.value : '',
        mb_key: '',
        abuseip_key: elements.ramKeyAbuseIp ? elements.ramKeyAbuseIp.value : ''
      };

      try {
        const engineLabel = volPath.includes('Built-in') ? 'Built-in Rust Engine' : volPath;
        logMessage('VOLATILITY', `Starting memory analysis [Engine: ${engineLabel}] [Profile: ${config.profile}]...`);
        logRamMessage('VOLATILITY', `Starting memory analysis [Engine: ${engineLabel}] [Profile: ${config.profile}]...`);
        elements.btnStartRamAnalysis.disabled = true;
        elements.btnStartRamAnalysis.textContent = 'Running Analysis...';

        await invoke('start_volatility_analysis', { config });
      } catch (err) {
        logMessage('ERROR', 'Failed to start Volatility analysis: ' + err);
        logRamMessage('ERROR', 'Failed to start Volatility analysis: ' + err);
        alert('Failed to start Volatility analysis: ' + err);
        elements.btnStartRamAnalysis.disabled = false;
        elements.btnStartRamAnalysis.textContent = '▶ Start Volatility Analysis';
      }
    });
  }

  // YARA Scanner Handlers
  if (elements.btnBrowseYaraImage) {
    elements.btnBrowseYaraImage.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'dd' });
        if (file) {
          elements.yaraScanImagePath.value = file;
          logMessage('SYSTEM', 'Selected target image for YARA scan: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse image: ' + e);
      }
    });
  }

  if (elements.btnBrowseYaraRulesFile) {
    elements.btnBrowseYaraRulesFile.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'yar' });
        if (file) {
          elements.yaraScanRulesPath.value = file;
          logMessage('SYSTEM', 'Selected YARA rules file: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse rules file: ' + e);
      }
    });
  }

  if (elements.btnBrowseYaraRulesDir) {
    elements.btnBrowseYaraRulesDir.addEventListener('click', async () => {
      try {
        const folder = await invoke('browse_folder');
        if (folder) {
          elements.yaraScanRulesPath.value = folder;
          logMessage('SYSTEM', 'Selected YARA rules directory: ' + folder);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse rules directory: ' + e);
      }
    });
  }

  if (elements.btnStartYaraScan) {
    elements.btnStartYaraScan.addEventListener('click', async (e) => {
      e.preventDefault();
      const imagePath = elements.yaraScanImagePath?.value;
      const rulesPath = elements.yaraScanRulesPath?.value;

      if (!imagePath || !rulesPath) {
        alert('Please select both a target image/dump file and a YARA ruleset path.');
        return;
      }

      try {
        logMessage('YARA', `Starting On-Demand YARA scan against ${imagePath}...`);
        elements.btnStartYaraScan.disabled = true;
        elements.btnStartYaraScan.textContent = 'Scanning...';

        await invoke('scan_image_yara', { imagePath, rulesPath });
        logMessage('SUCCESS', 'YARA scan background job initiated. Results will stream below.');
      } catch (err) {
        logMessage('ERROR', 'Failed to start YARA scan: ' + err);
        alert('Failed to start YARA scan: ' + err);
      } finally {
        elements.btnStartYaraScan.disabled = false;
        elements.btnStartYaraScan.innerHTML = '<span class="material-symbols-outlined text-[20px]">play_arrow</span>Start YARA Scan';
      }
    });
  }

  // PGP Button Listeners
  const btnBrowsePgpManifest = document.getElementById('btn-browse-pgp-manifest');
  if (btnBrowsePgpManifest) {
    btnBrowsePgpManifest.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'txt' });
        if (file) {
          document.getElementById('pgp-manifest-path').value = file;
          logMessage('SYSTEM', 'Selected manifest file for PGP verification: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse manifest file: ' + e);
      }
    });
  }

  const btnBrowsePgpSig = document.getElementById('btn-browse-pgp-sig');
  if (btnBrowsePgpSig) {
    btnBrowsePgpSig.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'asc' });
        if (file) {
          document.getElementById('pgp-sig-path').value = file;
          logMessage('SYSTEM', 'Selected signature file: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse signature file: ' + e);
      }
    });
  }

  const btnGeneratePgpKey = document.getElementById('btn-generate-pgp-key');
  if (btnGeneratePgpKey) {
    btnGeneratePgpKey.addEventListener('click', async () => {
      const userIdInput = document.getElementById('pgp-user-id-input');
      const userId = userIdInput ? userIdInput.value : 'OpenForensic Workstation <dfir@openforensic.local>';
      try {
        logMessage('SYSTEM', 'Generating new 3072-bit PGP signing keypair...');
        btnGeneratePgpKey.disabled = true;
        btnGeneratePgpKey.textContent = 'Generating...';
        const info = await invoke('pgp_generate_new_key', { userId });
        renderPgpKeyInfo(info);
        logMessage('SYSTEM', `PGP keypair generated successfully. Key ID: ${info.key_id}`);
      } catch (e) {
        logMessage('ERROR', 'Failed to generate PGP keypair: ' + e);
        alert('Failed to generate PGP keypair: ' + e);
      } finally {
        btnGeneratePgpKey.disabled = false;
        btnGeneratePgpKey.textContent = '⚡ Generate / Reset Keypair';
      }
    });
  }

  const btnVerifyPgpManifest = document.getElementById('btn-verify-pgp-manifest');
  if (btnVerifyPgpManifest) {
    btnVerifyPgpManifest.addEventListener('click', async () => {
      const manifestPath = document.getElementById('pgp-manifest-path').value;
      let sigPath = document.getElementById('pgp-sig-path').value;
      if (!manifestPath) {
        alert('Please select a manifest or report file to verify.');
        return;
      }
      if (!sigPath) {
        sigPath = manifestPath + '.asc';
      }
      const resultDiv = document.getElementById('pgp-verify-result');
      resultDiv.style.display = 'block';
      resultDiv.style.background = 'rgba(255, 255, 0, 0.1)';
      resultDiv.style.border = '1px solid #eab308';
      resultDiv.style.color = '#eab308';
      resultDiv.innerHTML = '🔍 Verifying cryptographic PGP signature...';

      try {
        logMessage('SYSTEM', `Verifying PGP signature for ${manifestPath} against ${sigPath}...`);
        const report = await invoke('pgp_verify_manifest', { manifestPath, sigPath, pubKeyPem: null });
        if (report.is_valid) {
          resultDiv.style.background = 'rgba(16, 185, 129, 0.15)';
          resultDiv.style.border = '1px solid #10b981';
          resultDiv.style.color = '#10b981';
          resultDiv.innerHTML = `✅ <strong>VALID PGP SIGNATURE & PROVENANCE VERIFIED</strong><br><br>` +
            `<strong>Signer Fingerprint:</strong> ${report.signer_fingerprint}<br>` +
            `<strong>Signer Identity:</strong> ${report.signer_user_id}<br>` +
            `<strong>Status:</strong> ${report.message}`;
          logMessage('SYSTEM', `PGP verification successful for ${manifestPath}. Signer: ${report.signer_user_id}`);
        } else {
          resultDiv.style.background = 'rgba(239, 68, 68, 0.15)';
          resultDiv.style.border = '1px solid #ef4444';
          resultDiv.style.color = '#ef4444';
          resultDiv.innerHTML = `❌ <strong>PGP VERIFICATION FAILED / TAMPER DETECTED</strong><br><br>` +
            `<strong>Status:</strong> ${report.message}`;
          logMessage('ERROR', `PGP verification FAILED for ${manifestPath}: ${report.message}`);
        }
      } catch (e) {
        resultDiv.style.background = 'rgba(239, 68, 68, 0.15)';
        resultDiv.style.border = '1px solid #ef4444';
        resultDiv.style.color = '#ef4444';
        resultDiv.innerHTML = `❌ <strong>VERIFICATION ERROR:</strong> ${e}`;
        logMessage('ERROR', `PGP verification error: ${e}`);
      }
    });
  }

  // Listen to Tauri Backend events
  listen('acquisition-event', (event) => {
    handleBackendEvent(event.payload);
  });

  listen('volatility-event', (event) => {
    const { type, data } = event.payload;
    if (type === 'Log') {
      const cleanData = data.startsWith('[VOLATILITY] ') ? data.slice(13) : (data.startsWith('[VOLATILITY]') ? data.slice(12).trimStart() : data);
      logMessage('VOLATILITY', cleanData);
      logRamMessage('VOLATILITY', cleanData);
    } else if (type === 'Error') {
      logMessage('ERROR', '[VOLATILITY ERROR] ' + data);
      logRamMessage('ERROR', '[VOLATILITY ERROR] ' + data);
      alert('Volatility Analysis Error:\n' + data);
      if (elements.btnStartRamAnalysis) {
        elements.btnStartRamAnalysis.disabled = false;
        elements.btnStartRamAnalysis.textContent = '▶ Start Volatility Analysis';
      }
    } else if (type === 'Finished') {
      logMessage('SYSTEM', '=== VOLATILITY ANALYSIS COMPLETED ===');
      logRamMessage('SYSTEM', '=== VOLATILITY ANALYSIS COMPLETED ===');
      alert('Volatility Analysis Completed!');
      if (elements.btnStartRamAnalysis) {
        elements.btnStartRamAnalysis.disabled = false;
        elements.btnStartRamAnalysis.textContent = '▶ Start Volatility Analysis';
      }
    }
  });
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.add('hidden'));
  document.querySelectorAll('.tab-content').forEach(panel => panel.classList.add('hidden'));

  if (tabName === 'imaging') {
    document.getElementById('btn-tab-imaging').classList.add('active');
    document.getElementById('tab-imaging-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.remove('hidden');
  } else if (tabName === 'triage') {
    document.getElementById('btn-tab-triage').classList.add('active');
    document.getElementById('tab-triage-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'live') {
    document.getElementById('btn-tab-live').classList.add('active');
    document.getElementById('tab-live-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
    // Auto-refresh volumes if empty
    const volSelect = document.getElementById('live-volume-select');
    if (volSelect && volSelect.options.length <= 1) {
      document.getElementById('btn-refresh-volumes').click();
    }
  } else if (tabName === 'timeline') {
    document.getElementById('btn-tab-timeline').classList.add('active');
    document.getElementById('tab-timeline-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'cases') {
    document.getElementById('btn-tab-cases').classList.add('active');
    document.getElementById('tab-cases-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'ram') {
    document.getElementById('btn-tab-ram').classList.add('active');
    document.getElementById('tab-ram-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'ram-viewer') {
    document.getElementById('btn-tab-ram-viewer')?.classList.add('active');
    document.getElementById('tab-ram-viewer-content')?.classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
    if (typeof refreshRamDbList === 'function') refreshRamDbList();
  } else if (tabName === 'yara') {
    document.getElementById('btn-tab-yara')?.classList.add('active');
    document.getElementById('tab-yara-content')?.classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'pgp') {
    document.getElementById('btn-tab-pgp').classList.add('active');
    document.getElementById('tab-pgp-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  }

  updateAnalysisLockScreens();
}

function setImagingMode(mode) {
  if (state.activeJob) return;

  state.imagingMode = mode;
  if (mode === 'Physical') {
    elements.modePhysical?.classList.add('active');
    elements.modeLogical?.classList.remove('active');
    elements.modeImage?.classList.remove('active');
    elements.physicalContainer?.classList.remove('hidden');
    elements.logicalContainer?.classList.add('hidden');
    elements.imageMountContainer?.classList.add('hidden');
    logMessage('SYSTEM', 'Switched to Physical Sector-by-Sector imaging mode.');
  } else if (mode === 'Logical') {
    elements.modePhysical?.classList.remove('active');
    elements.modeLogical?.classList.add('active');
    elements.modeImage?.classList.remove('active');
    elements.physicalContainer?.classList.add('hidden');
    elements.logicalContainer?.classList.remove('hidden');
    elements.imageMountContainer?.classList.add('hidden');
    logMessage('SYSTEM', 'Switched to Logical File/Directory imaging mode.');
  } else if (mode === 'Image') {
    elements.modePhysical?.classList.remove('active');
    elements.modeLogical?.classList.remove('active');
    elements.modeImage?.classList.add('active');
    elements.physicalContainer?.classList.add('hidden');
    elements.logicalContainer?.classList.add('hidden');
    elements.imageMountContainer?.classList.remove('hidden');
    refreshMountedImages();
    logMessage('SYSTEM', 'Switched to Disk Image Mounting & Analysis mode.');
  }
}

async function mountDiskImage() {
  const imagePath = elements.mountImagePath?.value || '';
  if (!imagePath) {
    alert('Please select a forensic disk image file first.');
    return;
  }
  const readOnly = elements.mountReadOnly ? elements.mountReadOnly.checked : true;
  const customPoint = elements.mountCustomPoint?.value?.trim() || null;

  logMessage('SYSTEM', `Attempting to mount disk image: ${imagePath} (ReadOnly: ${readOnly})...`);
  try {
    const info = await invoke('mount_disk_image', { imagePath, readOnly, customMountPoint: customPoint });
    logMessage('SUCCESS', `Successfully mounted image to: ${info.mount_point} (${info.filesystem}, ${info.size_gb} GB)`);
    refreshMountedImages();
  } catch (err) {
    logMessage('ERROR', `Failed to mount disk image: ${err}`);
    alert(`Mount Error: ${err}`);
  }
}

async function unmountDiskImage() {
  const imagePath = elements.mountImagePath?.value || '';
  if (!imagePath) {
    alert('Please select or specify the image path to unmount.');
    return;
  }
  logMessage('SYSTEM', `Unmounting disk image: ${imagePath}...`);
  try {
    const res = await invoke('unmount_disk_image', { imagePath });
    logMessage('SUCCESS', res);
    refreshMountedImages();
  } catch (err) {
    logMessage('ERROR', `Failed to unmount disk image: ${err}`);
    alert(`Unmount Error: ${err}`);
  }
}

async function refreshMountedImages() {
  if (!elements.mountedImagesBody) return;
  try {
    const mounts = await invoke('list_mounted_images');
    if (!mounts || mounts.length === 0) {
      elements.mountedImagesBody.innerHTML = '<tr><td colspan="6" class="py-4 text-center text-outline italic">No forensic disk images mounted.</td></tr>';
      return;
    }
    elements.mountedImagesBody.innerHTML = '';
    mounts.forEach(m => {
      const tr = document.createElement('tr');
      tr.className = 'hover:bg-surface-container-low transition-colors';
      const name = m.image_path.split(/[/\\]/).pop();
      tr.innerHTML = `
        <td class="py-2.5 px-3 font-bold text-primary">${m.mount_point}</td>
        <td class="py-2.5 px-3 truncate max-w-xs" title="${m.image_path}">${name}</td>
        <td class="py-2.5 px-3">${m.filesystem}</td>
        <td class="py-2.5 px-3">${m.size_gb}</td>
        <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[11px] font-bold ${m.is_read_only ? 'bg-primary/10 text-primary' : 'bg-error/10 text-error'}">${m.is_read_only ? 'RO' : 'RW'}</span></td>
        <td class="py-2.5 px-3 text-right space-x-2">
          <button class="btn-triage-mounted px-2.5 py-1 bg-secondary text-on-secondary hover:bg-secondary/90 font-bold text-[11px] rounded transition-all shadow-sm" data-point="${m.mount_point}">
            ⚡ Triage Disk
          </button>
          <button class="btn-unmount-row px-2.5 py-1 bg-error/10 text-error hover:bg-error/20 font-bold text-[11px] rounded transition-all" data-path="${m.image_path}">
            Unmount
          </button>
        </td>
      `;
      elements.mountedImagesBody.appendChild(tr);
    });

    elements.mountedImagesBody.querySelectorAll('.btn-triage-mounted').forEach(btn => {
      btn.addEventListener('click', () => {
        const point = btn.getAttribute('data-point');
        if (point) {
          switchTab('triage');
          if (elements.triageModeMounted) elements.triageModeMounted.click();
          if (elements.triageSourceRoot) elements.triageSourceRoot.value = point;
          logMessage('SYSTEM', `Pre-selected mounted disk volume ${point} for Triage Analysis.`);
        }
      });
    });

    elements.mountedImagesBody.querySelectorAll('.btn-unmount-row').forEach(btn => {
      btn.addEventListener('click', async () => {
        const path = btn.getAttribute('data-path');
        if (path) {
          try {
            await invoke('unmount_disk_image', { imagePath: path });
            refreshMountedImages();
          } catch (e) {
            alert(`Failed to unmount: ${e}`);
          }
        }
      });
    });
  } catch (err) {
    console.error('Failed to list mounted images:', err);
  }
}

// Check checkpoint
async function checkCheckpointExists(destPath) {
  try {
    const exists = await invoke('check_checkpoint', { destPath });
    if (exists) {
      elements.btnResumeAcquisition.classList.remove('hidden');
      logMessage('SYSTEM', 'Detected partial checkpoint. You can resume this acquisition job.');
    } else {
      elements.btnResumeAcquisition.classList.add('hidden');
    }
  } catch (e) {
    console.error(e);
  }
}

// Device Scanner
async function doRescan() {
  if (state.activeJob) return;

  elements.deviceList.innerHTML = '<div class="info-message">Scanning system block devices...</div>';
  logMessage('SYSTEM', 'Scanning block devices...');

  try {
    const devs = await invoke('scan_devices');
    state.devices = devs;
    elements.deviceList.innerHTML = '';

    if (devs.length === 0) {
      elements.deviceList.innerHTML = '<div class="info-message">No physical devices detected. Run in Elevated Mode.</div>';
      return;
    }

    devs.forEach((dev, idx) => {
      const card = document.createElement('div');
      card.className = 'device-card';
      if (state.selectedDeviceIndex === idx) {
        card.classList.add('selected');
      }

      let partitionsHtml = '';
      if (dev.partitions && dev.partitions.length > 0) {
        partitionsHtml = `
          <div class="partition-list">
            ${dev.partitions.map(part => `
              <div class="partition-item">
                <span class="partition-icon">↳ 📂</span>
                <span class="partition-name">${part.name}</span>
                <span class="partition-type">[${part.fs_type}]</span>
                <span class="partition-size">${formatBytes(part.size)}</span>
              </div>
            `).join('')}
          </div>
        `;
      }

      card.innerHTML = `
        <div class="device-icon-row">
          <div class="device-icon">💾</div>
          <div class="device-info">
            <div class="device-meta-row">
              <span class="device-path">${dev.path} <span class="chip chip-blue">${dev.device_type}</span></span>
              <span class="device-size">${formatBytes(dev.size)}</span>
            </div>
            <div class="device-model">${dev.vendor} ${dev.model} ${dev.serial ? '(S/N: ' + dev.serial + ')' : ''}</div>
            <div class="device-health-row">⚡ Health: <span class="chip chip-green">${dev.smart_health || 'Healthy (100% Life)'}</span></div>
          </div>
        </div>
        ${partitionsHtml}
      `;

      card.addEventListener('click', () => {
        if (state.activeJob) return;
        state.selectedDeviceIndex = idx;

        // Remove selection from others
        document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');

        logMessage('SYSTEM', `Selected device: ${dev.path} (${formatBytes(dev.size)})`);

        // Populate default destination path
        if (!elements.inputDestPath.value) {
          const cleanName = dev.name.replace(/\\\\.\\/g, '').replace(/[\/\\?%*:|"<>\s]/g, '_');
          elements.inputDestPath.value = `C:\\${cleanName}.dd`;
          checkCheckpointExists(`C:\\${cleanName}.dd`);
        }
      });

      elements.deviceList.appendChild(card);
    });

    logMessage('SYSTEM', `Discovered ${devs.length} device(s).`);
  } catch (err) {
    elements.deviceList.innerHTML = `<div class="info-message error-text">Failed to scan devices: ${err}</div>`;
    logMessage('ERROR', 'Scan failed: ' + err);
  }
}

// Trigger Acquisition
async function handleStartAcquisition(isResume) {
  if (state.activeJob) return;

  // Validate form inputs
  if (!elements.inputEvidenceId.value || !elements.inputCaseNumber.value || !elements.inputExaminer.value) {
    alert('Please fill out all required configuration fields (Evidence ID, Case Number, Examiner Name).');
    return;
  }

  let sourcePath = '';
  if (state.imagingMode === 'Physical') {
    if (state.selectedDeviceIndex === null) {
      alert('Please select a source physical block device.');
      return;
    }
    sourcePath = state.devices[state.selectedDeviceIndex].path;
  } else {
    sourcePath = elements.logicalSourceInput.value;
    if (!sourcePath) {
      alert('Please select a source logical directory.');
      return;
    }
  }

  const destPath = elements.inputDestPath.value;
  if (!destPath) {
    alert('Please specify a destination path.');
    return;
  }

  // Collect active hashes
  const hash_algorithms = [];
  if (elements.hashMd5.checked) hash_algorithms.push('MD5');
  if (elements.hashSha1.checked) hash_algorithms.push('SHA1');
  if (elements.hashSha256.checked) hash_algorithms.push('SHA256');
  if (elements.hashSha512.checked) hash_algorithms.push('SHA512');

  if (hash_algorithms.length === 0) {
    alert('Please enable at least one cryptographic hash algorithm.');
    return;
  }

  // Calculate splitting size in MB
  let split_size_mb = null;
  const splitVal = elements.selectSplit.value;
  if (splitVal === 'Custom') {
    const parsed = parseInt(elements.inputSplitSize.value, 10);
    if (isNaN(parsed) || parsed <= 0) {
      alert('Please enter a valid custom split size in MB.');
      return;
    }
    split_size_mb = parsed;
  } else if (splitVal !== 'None') {
    split_size_mb = parseInt(splitVal, 10);
  }

  const read_verification = elements.checkReadVerification.checked;

  const config = {
    imaging_mode: state.imagingMode,
    source_path: sourcePath,
    dest_path: destPath,
    evidence_id: elements.inputEvidenceId.value,
    notes: elements.inputNotes.value,
    case_number: elements.inputCaseNumber.value,
    examiner: elements.inputExaminer.value,
    format_mode: elements.selectFormat.value,
    hash_verification: elements.selectVerification.value,
    block_size_kb: parseInt(elements.selectBlocksize.value, 10),
    hash_algorithms,
    compression: elements.selectCompression.value,
    resume_mode: isResume,
    split_size_mb,
    read_verification,
    keywords: elements.inputKeywords.value ? elements.inputKeywords.value.split(',').map(s => s.trim()).filter(s => s.length > 0) : [],
    yara_rules_path: elements.inputYaraPath.value || null,
    sparse: elements.checkSparse.checked,
    digital_signature: elements.checkDigitalSignature.checked
  };

  try {
    state.activeJob = true;
    toggleUIJobActive(true);

    // Clear display progress stats
    resetStats();

    logMessage('SYSTEM', 'Initiating acquisition job...');
    await invoke('start_acquisition', { configInput: config });
  } catch (e) {
    state.activeJob = false;
    toggleUIJobActive(false);
    logMessage('ERROR', 'Failed to start acquisition: ' + e);
    alert('Failed to start: ' + e);
  }
}

// Toggle layout state when job starts/cancels
function toggleUIJobActive(active) {
  if (active) {
    elements.monitorIdle.classList.add('hidden');
    elements.monitorActive.classList.remove('hidden');
    // Disable configuration forms
    toggleFormInputs(true);
    elements.btnRescan.disabled = true;
  } else {
    elements.monitorIdle.classList.remove('hidden');
    elements.monitorActive.classList.add('hidden');
    // Enable configuration forms
    toggleFormInputs(false);
    elements.btnRescan.disabled = false;
    // Check destination file again for resume state
    checkCheckpointExists(elements.inputDestPath.value);
  }
}

function toggleFormInputs(disabled) {
  const inputs = [
    elements.inputEvidenceId, elements.inputCaseNumber, elements.inputExaminer, elements.inputNotes,
    elements.selectFormat, elements.selectVerification, elements.selectBlocksize, elements.selectCompression,
    elements.selectSplit, elements.inputSplitSize, elements.checkReadVerification,
    elements.hashMd5, elements.hashSha1, elements.hashSha256, elements.hashSha512,
    elements.btnBrowseSource, elements.btnBrowseDest,
    elements.inputKeywords, elements.checkSparse, elements.checkDigitalSignature,
    elements.inputYaraPath, elements.btnBrowseYara,
    document.getElementById('btn-browse-triage-dest'),
    document.getElementById('btn-start-triage'),
    document.getElementById('btn-browse-mount-src'),
    document.getElementById('btn-browse-mount-point'),
    document.getElementById('btn-verify-image'),
    document.getElementById('btn-mount-image')
  ];
  inputs.forEach(input => {
    if (input) input.disabled = disabled;
  });
}

function resetStats() {
  elements.txtStatSpeed.textContent = '0.00 MB/s';
  elements.txtStatEta.textContent = '0s';
  elements.txtStatBad.textContent = '0';
  elements.txtStatPercent.textContent = '0.0%';
  elements.progressBarFill.style.width = '0%';
  elements.txtBytesProgress.textContent = '0 B / 0 B';
}

// Handle Tauri emitted progress events
function handleBackendEvent(event) {
  const { type, data } = event;

  if (type === 'Log') {
    logMessage('ACQUISITION', data);
  } else if (type === 'Progress') {
    const { bytes_read, total_size, speed_bps, bad_sectors } = data;

    // Percentage
    const pct = total_size > 0 ? (bytes_read / total_size * 100) : 0;
    elements.txtStatPercent.textContent = pct.toFixed(1) + '%';
    elements.progressBarFill.style.width = pct.toFixed(1) + '%';

    // Speed
    const speedMb = speed_bps / 1000000;
    elements.txtStatSpeed.textContent = speedMb.toFixed(2) + ' MB/s';

    // ETA
    const remainingBytes = total_size - bytes_read;
    const etaSecs = speed_bps > 0 ? Math.ceil(remainingBytes / speed_bps) : 0;
    elements.txtStatEta.textContent = formatDuration(etaSecs);

    // Bad Sectors
    elements.txtStatBad.textContent = bad_sectors.toString();
    if (bad_sectors > 0) {
      elements.txtStatBad.className = 'stat-val text-red';
    } else {
      elements.txtStatBad.className = 'stat-val text-teal';
    }

    // Bytes label
    elements.txtBytesProgress.textContent = `${formatBytes(bytes_read)} / ${formatBytes(total_size)}`;
  } else if (type === 'Finished') {
    const { bytes_read, bad_sectors, hashes } = data;
    logMessage('SYSTEM', '=== ACQUISITION COMPLETED SUCCESSFULLY ===');
    logMessage('SYSTEM', `Total Imaged Size: ${formatBytes(bytes_read)}`);
    logMessage('SYSTEM', `Bad Sectors Discovered: ${bad_sectors}`);

    for (const algo in hashes) {
      logMessage('ACQUISITION', `${algo}: ${hashes[algo]}`);
    }

    alert('Acquisition Job Completed and Verified!');
    state.activeJob = false;
    toggleUIJobActive(false);
  } else if (type === 'KeywordHit') {
    logMessage('WARNING', `[KEYWORD HIT] Found '${data.keyword}' at offset ${data.offset}`);
  } else if (type === 'YaraHit') {
    const tags = data.tags.length > 0 ? ` [${data.tags.join(', ')}]` : '';
    logMessage('WARNING', `[YARA HIT] Rule '${data.rule_name}'${tags} matched at offset ${data.offset}`);
  } else if (type === 'Error') {
    logMessage('ERROR', 'Critical backend error: ' + data);
    alert('Forensic Acquisition Error:\n' + data);
    state.activeJob = false;
    toggleUIJobActive(false);
  }
}

// Log view utility
function logMessage(level, text) {
  const entry = document.createElement('div');
  entry.className = `log-entry log-${level.toLowerCase()}`;

  const timestamp = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
  entry.textContent = `[${timestamp} IST] [${level}] ${text}`;

  elements.consoleLogs.appendChild(entry);

  // Auto scroll to bottom
  elements.consoleLogs.scrollTop = elements.consoleLogs.scrollHeight;
}

function logRamMessage(level, text) {
  if (!elements.ramConsoleLogs) return;

  // Clear initial placeholder if present
  if (elements.ramConsoleLogs.children.length === 1 && elements.ramConsoleLogs.children[0].classList.contains('italic')) {
    elements.ramConsoleLogs.innerHTML = '';
  }

  const entry = document.createElement('div');
  entry.className = `log-entry log-${level.toLowerCase()} py-0.5 border-b border-outline-variant/20`;

  const timestamp = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
  entry.textContent = `[${timestamp} IST] [${level}] ${text}`;

  elements.ramConsoleLogs.appendChild(entry);
  elements.ramConsoleLogs.scrollTop = elements.ramConsoleLogs.scrollHeight;
}

// Helper formatting utilities
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1000;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(secs) {
  if (secs === 0) return '0s';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;

  let str = '';
  if (h > 0) str += `${h}h `;
  if (m > 0 || h > 0) str += `${m}m `;
  str += `${s}s`;
  return str;
}

// Boot UI
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Case Management Functions
// Case Management Functions
let activeSelectedCaseId = null;

async function loadCases() {
  const container = document.getElementById('cases-list');
  if (!container) return;
  container.innerHTML = '<div class="info-message text-body-sm text-outline p-4">Loading cases...</div>';
  try {
    const cases = await invoke('get_cases');
    if (cases.length === 0) {
      container.innerHTML = '<div class="info-message text-body-sm text-outline p-4">No cases found. Click "New Case Folder" to initialize.</div>';
      return;
    }

    let html = '<div class="flex items-center gap-3 py-1">';
    for (const c of cases) {
      const isSelected = activeSelectedCaseId === c.id;
      const borderClass = isSelected ? 'border-primary ring-2 ring-primary/30 bg-primary/5' : 'border-outline-variant bg-surface hover:border-primary/50';
      const badge = c.case_root ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/10 text-green-600 border border-green-500/20">Unified Folder</span>' : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-600 border border-amber-500/20">Legacy</span>';
      
      html += `
        <div onclick="selectCase(${c.id})" class="cursor-pointer shrink-0 w-64 p-3 rounded-xl border ${borderClass} shadow-sm transition-all flex flex-col justify-between h-20">
          <div class="flex items-center justify-between gap-2">
            <span class="font-mono font-bold text-body-sm text-on-surface truncate" title="${c.case_number}">${c.case_number}</span>
            ${badge}
          </div>
          <div class="flex items-center justify-between text-[11px] text-outline mt-1">
            <span class="truncate max-w-[120px]">${c.examiner_name}</span>
            <span>${c.created_at.split(' ')[0]}</span>
          </div>
        </div>
      `;
    }
    html += '</div>';
    container.innerHTML = html;

    if (activeSelectedCaseId) {
      selectCase(activeSelectedCaseId);
    } else if (cases.length > 0) {
      selectCase(cases[0].id);
    }
  } catch (e) {
    container.innerHTML = `<div class="info-message text-body-sm text-error p-4">Failed to load cases: ${e}</div>`;
  }
}

async function selectCase(caseId) {
  activeSelectedCaseId = caseId;
  await loadCasesRibbonOnly();
  
  const detailContainer = document.getElementById('case-detail-content');
  const breadcrumb = document.getElementById('case-detail-breadcrumb');
  if (!detailContainer) return;
  
  detailContainer.innerHTML = '<div class="p-8 text-center text-outline"><span class="material-symbols-outlined animate-spin text-[32px] mb-2">sync</span><p>Loading case architecture...</p></div>';

  try {
    const details = await invoke('get_case_details', { caseId });
    if (breadcrumb) breadcrumb.textContent = details.case.case_number;

    let treeHtml = '';
    if (details.case.case_root) {
      try {
        const tree = await invoke('get_case_folder_structure', { caseId });
        treeHtml = `
          <div class="bg-surface border border-outline-variant rounded-xl p-6 shadow-sm mb-6">
            <div class="flex items-center justify-between pb-4 mb-4 border-b border-outline-variant">
              <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                  <span class="material-symbols-outlined text-[24px]">folder_managed</span>
                </div>
                <div>
                  <h4 class="text-headline font-bold text-on-surface">Unified Forensic Case Tree</h4>
                  <p class="text-data-mono text-outline font-mono">${tree.case_root}</p>
                </div>
              </div>
              <div class="flex items-center gap-2">
                <button onclick="setActiveWorkspaceCase('${details.case.case_number}', ${caseId})" class="px-4 py-2 bg-primary text-on-primary font-bold text-body-sm rounded-lg shadow-sm hover:opacity-90 transition-all flex items-center gap-1.5">
                  <span class="material-symbols-outlined text-[18px]">check_circle</span>Set Active Workspace
                </button>
                <button onclick="exportCaseReport(${caseId}, '${details.case.case_number}')" class="px-3.5 py-2 border border-outline-variant rounded-lg hover:bg-surface-container text-on-surface font-semibold text-body-sm flex items-center gap-1.5 transition-colors">
                  <span class="material-symbols-outlined text-[18px]">file_download</span>Export HTML Report
                </button>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-5 gap-3 mb-4">
        `;
        
        for (const f of tree.folders) {
          const sizeMB = (f.total_size_bytes / (1024 * 1024)).toFixed(2);
          treeHtml += `
            <div class="p-3 bg-surface-container-lowest border border-outline-variant rounded-lg flex flex-col justify-between">
              <div class="flex items-center gap-2 mb-2">
                <span class="material-symbols-outlined text-amber-500 text-[20px]">folder</span>
                <span class="font-bold text-body-sm text-on-surface">${f.name}/</span>
              </div>
              <div class="flex items-center justify-between text-[11px] text-outline font-mono">
                <span>${f.file_count} items</span>
                <span class="font-bold text-on-surface-variant">${sizeMB} MB</span>
              </div>
            </div>
          `;
        }

        treeHtml += `
            </div>
            <div class="flex items-center gap-4 text-data-mono text-outline bg-surface-container-low p-3 rounded-lg border border-outline-variant">
              <div class="flex items-center gap-1.5">
                <span class="material-symbols-outlined text-green-600 text-[18px]">description</span>
                <span>Manifest: <strong class="font-mono text-on-surface">${tree.manifest_path.split('\\').pop() || tree.manifest_path.split('/').pop()}</strong></span>
              </div>
              <div class="h-4 w-px bg-outline-variant"></div>
              <div class="flex items-center gap-1.5">
                <span class="material-symbols-outlined text-blue-600 text-[18px]">storage</span>
                <span>Portable DB: <strong class="font-mono text-on-surface">openforensic.db</strong></span>
              </div>
            </div>
          </div>
        `;
      } catch (err) {
        treeHtml = `<div class="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-600 text-body-sm mb-6">Folder structure warning: ${err}</div>`;
      }
    } else {
      treeHtml = `
        <div class="bg-surface border border-outline-variant rounded-xl p-6 shadow-sm mb-6 flex items-center justify-between">
          <div>
            <h4 class="text-headline font-bold text-on-surface">Legacy Case (No Folder Assigned)</h4>
            <p class="text-body-sm text-on-surface-variant">This case was created without a unified directory structure.</p>
          </div>
          <button onclick="exportCaseReport(${caseId}, '${details.case.case_number}')" class="px-4 py-2 bg-primary text-on-primary font-bold text-body-sm rounded-lg shadow-sm hover:opacity-90 transition-all flex items-center gap-1.5">
            <span class="material-symbols-outlined text-[18px]">file_download</span>Export Report
          </button>
        </div>
      `;
    }

    let evHtml = '<h4 class="text-headline font-bold text-on-surface mb-3">Chain of Custody & Evidence Log</h4>';
    if (details.evidence.length === 0) {
      evHtml += '<div class="p-6 bg-surface border border-outline-variant rounded-xl text-center text-outline">No evidence acquired under this case yet.</div>';
    } else {
      evHtml += '<div class="space-y-4">';
      for (const ev of details.evidence) {
        evHtml += `
          <div class="bg-surface border border-outline-variant rounded-xl overflow-hidden shadow-sm">
            <div class="px-5 py-3 bg-surface-container-low border-b border-outline-variant flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-primary text-[20px]">hard_drive</span>
                <span class="font-bold text-body-md text-on-surface">${ev.item.evidence_tag}</span>
                <span class="text-data-mono text-outline font-mono">(${ev.item.source_path})</span>
              </div>
              <span class="text-[11px] text-outline">${ev.item.created_at}</span>
            </div>
            <div class="p-4">
        `;
        if (ev.logs.length === 0) {
          evHtml += '<p class="text-body-sm text-outline">No acquisition jobs recorded.</p>';
        } else {
          evHtml += '<table class="w-full text-left border-collapse text-body-sm"><tr class="border-b border-outline-variant text-outline text-label-caps"><th class="pb-2">Status</th><th class="pb-2">Destination</th><th class="pb-2">Format</th><th class="pb-2">Timestamp</th></tr>';
          for (const l of ev.logs) {
            const statusBadge = l.status === 'SUCCESS' ? '<span class="px-2 py-0.5 bg-green-500/10 text-green-600 border border-green-500/20 rounded text-[11px] font-bold">SUCCESS</span>' : `<span class="px-2 py-0.5 bg-error/10 text-error border border-error/20 rounded text-[11px] font-bold">${l.status}</span>`;
            evHtml += `
              <tr class="border-b border-outline-variant/40 last:border-0 font-mono">
                <td class="py-2.5">${statusBadge}</td>
                <td class="py-2.5 max-w-xs truncate" title="${l.dest_path}">${l.dest_path}</td>
                <td class="py-2.5">${l.format}</td>
                <td class="py-2.5 text-outline">${l.timestamp}</td>
              </tr>
            `;
          }
          evHtml += '</table>';
        }
        evHtml += '</div></div>';
      }
      evHtml += '</div>';
    }

    detailContainer.innerHTML = treeHtml + evHtml;
  } catch (e) {
    detailContainer.innerHTML = `<div class="p-4 bg-error/10 text-error border border-error/20 rounded-xl">Failed to load case details: ${e}</div>`;
  }
}

async function loadCasesRibbonOnly() {
  const container = document.getElementById('cases-list');
  if (!container) return;
  try {
    const cases = await invoke('get_cases');
    let html = '<div class="flex items-center gap-3 py-1">';
    for (const c of cases) {
      const isSelected = activeSelectedCaseId === c.id;
      const borderClass = isSelected ? 'border-primary ring-2 ring-primary/30 bg-primary/5' : 'border-outline-variant bg-surface hover:border-primary/50';
      const badge = c.case_root ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/10 text-green-600 border border-green-500/20">Unified Folder</span>' : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-600 border border-amber-500/20">Legacy</span>';
      
      html += `
        <div onclick="selectCase(${c.id})" class="cursor-pointer shrink-0 w-64 p-3 rounded-xl border ${borderClass} shadow-sm transition-all flex flex-col justify-between h-20">
          <div class="flex items-center justify-between gap-2">
            <span class="font-mono font-bold text-body-sm text-on-surface truncate" title="${c.case_number}">${c.case_number}</span>
            ${badge}
          </div>
          <div class="flex items-center justify-between text-[11px] text-outline mt-1">
            <span class="truncate max-w-[120px]">${c.examiner_name}</span>
            <span>${c.created_at.split(' ')[0]}</span>
          </div>
        </div>
      `;
    }
    html += '</div>';
    container.innerHTML = html;
  } catch (e) {}
}

async function setActiveWorkspaceCase(caseNumber, caseId) {
  const lbl = document.getElementById('active-case-label');
  const bc  = document.getElementById('breadcrumb-case');
  const inputCase = document.getElementById('input-case-number');
  if (lbl) lbl.textContent = caseNumber;
  if (bc)  bc.textContent  = caseNumber;
  if (inputCase) inputCase.value = caseNumber;
  
  try {
    const modOut = await invoke('get_case_export_path', { caseId, filename: 'triage_results.db', subfolder: 'ModuleOutput' });
    const btnTriageDest = document.getElementById('triage-dest-root');
    if (btnTriageDest) btnTriageDest.value = modOut.replace(/[/\\][^/\\]+$/, '');
    
    const expOut = await invoke('get_case_export_path', { caseId, filename: 'timeline.csv', subfolder: 'Export' });
    const btnTimeDest = document.getElementById('timeline-dest-dir');
    if (btnTimeDest) btnTimeDest.value = expOut.replace(/[/\\][^/\\]+$/, '');

    const imgOut = await invoke('get_case_export_path', { caseId, filename: `${caseNumber}_image.dd`, subfolder: 'Export' });
    const btnAcqDest = document.getElementById('input-dest-path');
    if (btnAcqDest && !btnAcqDest.value) btnAcqDest.value = imgOut;
  } catch (e) {}

  alert(`Active workspace set to ${caseNumber}. Output destinations pre-populated to the case folder!`);
}

async function exportCaseReport(caseId, caseNumber) {
  try {
    const file = await invoke('save_file_dialog', { ext: 'html' });
    if (file) {
      logMessage('SYSTEM', `Exporting report for case ${caseNumber} to ${file}...`);
      await invoke('export_case_report', { caseId: caseId, exportPath: file });
      logMessage('SYSTEM', `Report for case ${caseNumber} exported successfully.`);
    }
  } catch (e) {
    logMessage('ERROR', `Failed to export report for case ${caseNumber}: ` + e);
    alert('Failed to export report: ' + e);
  }
}

async function loadPgpKeyInfo() {
  const infoContainer = document.getElementById('pgp-key-info');
  if (!infoContainer) return;
  try {
    const info = await invoke('pgp_get_key_info');
    renderPgpKeyInfo(info);
  } catch (e) {
    infoContainer.innerHTML = `<div style="color: #ff5555;">No PGP keypair generated yet. Click "Generate / Reset Keypair" to initialize.</div>`;
  }
}

function renderPgpKeyInfo(info) {
  const infoContainer = document.getElementById('pgp-key-info');
  if (!infoContainer) return;
  infoContainer.innerHTML = `
    <div style="margin-bottom: 6px;"><strong style="color: var(--color-primary);">Key ID:</strong> <span>${info.key_id}</span></div>
    <div style="margin-bottom: 6px;"><strong style="color: var(--color-primary);">Fingerprint:</strong> <span style="word-break: break-all;">${info.fingerprint}</span></div>
    <div style="margin-bottom: 6px;"><strong style="color: var(--color-primary);">User Identity:</strong> <span>${info.user_id}</span></div>
    <div><strong style="color: var(--color-primary);">Private Key Available:</strong> <span style="color: ${info.has_private_key ? '#10b981' : '#ef4444'}; font-weight: bold;">${info.has_private_key ? 'YES (Active Signing Enabled)' : 'NO'}</span></div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════════
// RAM RESULTS VIEWER (.JSON DATABASE)
// ═══════════════════════════════════════════════════════════════════════════
let currentRamDbRecords = [];
let currentRamDbRunIndex = -1; // -1 for all runs

async function refreshRamDbList() {
  const dbSelect = document.getElementById('ram-db-select');
  if (!dbSelect) return;
  
  const imagePath = document.getElementById('ram-image-path')?.value || '';
  try {
    const dbFiles = await invoke('list_ram_databases', { dirPath: imagePath || null });
    const currentVal = dbSelect.value;
    dbSelect.innerHTML = '<option value="">Select database file…</option>';
    
    if (dbFiles && dbFiles.length > 0) {
      dbFiles.forEach(path => {
        const name = path.split(/[/\\]/).pop();
        const opt = document.createElement('option');
        opt.value = path;
        opt.textContent = name + ` (${path})`;
        if (path === currentVal || (dbFiles.length === 1 && !currentVal)) {
          opt.selected = true;
        }
        dbSelect.appendChild(opt);
      });
      if (dbSelect.value) {
        loadRamDatabase(dbSelect.value);
      }
    } else {
      dbSelect.innerHTML = '<option value="">No .json databases found in dump folder…</option>';
    }
  } catch (err) {
    console.error('Failed to list RAM databases:', err);
  }
}

async function loadRamDatabase(filePath) {
  if (!filePath) return;
  try {
    const jsonStr = await invoke('read_ram_database', { filePath });
    const records = JSON.parse(jsonStr);
    currentRamDbRecords = Array.isArray(records) ? records : [records];
    
    // Populate Run / Profile selector
    const runSelect = document.getElementById('ram-db-run-select');
    if (runSelect) {
      runSelect.innerHTML = '<option value="-1">All analysis runs (' + currentRamDbRecords.length + ' runs)</option>';
      currentRamDbRecords.forEach((rec, idx) => {
        const timeStr = new Date(rec.timestamp || Date.now()).toLocaleTimeString();
        const opt = document.createElement('option');
        opt.value = idx;
        opt.textContent = `Run #${idx + 1}: ${rec.profile || 'Unknown'} (${timeStr})`;
        runSelect.appendChild(opt);
      });
      runSelect.value = "-1";
      currentRamDbRunIndex = -1;
    }
    
    renderRamDbTable();
    updateRamDbMetadataBanner();
  } catch (err) {
    alert('Failed to load JSON database: ' + err);
    console.error(err);
  }
}

function updateRamDbMetadataBanner() {
  const banner = document.getElementById('ram-db-meta-banner');
  if (!banner || currentRamDbRecords.length === 0) return;
  
  banner.classList.remove('hidden');
  const targetRec = currentRamDbRunIndex >= 0 ? currentRamDbRecords[currentRamDbRunIndex] : currentRamDbRecords[currentRamDbRecords.length - 1];
  
  document.getElementById('meta-image-path').textContent = targetRec.image_path?.split(/[/\\]/).pop() || 'Unknown';
  document.getElementById('meta-profile').textContent = currentRamDbRunIndex >= 0 ? targetRec.profile : `Multiple (${currentRamDbRecords.length} runs)`;
  document.getElementById('meta-engine').textContent = targetRec.engine || 'Built-in Rust Engine';
  document.getElementById('meta-timestamp').textContent = new Date(targetRec.timestamp || Date.now()).toLocaleString();
  
  let totalRows = 0;
  if (currentRamDbRunIndex >= 0) {
    totalRows = targetRec.parsed_rows?.length || 0;
  } else {
    currentRamDbRecords.forEach(r => { totalRows += (r.parsed_rows?.length || 0); });
  }
  document.getElementById('meta-rows-count').textContent = totalRows.toLocaleString();
}

function renderRamDbTable() {
  const theadTr = document.getElementById('ram-db-thead-tr');
  const tbody = document.getElementById('ram-db-tbody');
  if (!theadTr || !tbody) return;
  
  if (!currentRamDbRecords || currentRamDbRecords.length === 0) {
    theadTr.innerHTML = '<th class="p-3">Select a JSON database to view results</th>';
    tbody.innerHTML = '<tr><td class="p-6 text-center text-on-surface-variant italic">No data loaded. Use "Open .json DB" or select from dropdown.</td></tr>';
    return;
  }
  
  let rows = [];
  if (currentRamDbRunIndex >= 0 && currentRamDbRecords[currentRamDbRunIndex]) {
    rows = currentRamDbRecords[currentRamDbRunIndex].parsed_rows || [];
  } else {
    currentRamDbRecords.forEach((rec, rIdx) => {
      const recRows = (rec.parsed_rows || []).map(row => ({
        '_Run': `#${rIdx + 1} (${rec.profile})`,
        ...row
      }));
      rows.push(...recRows);
    });
  }
  
  const searchVal = (document.getElementById('ram-db-search')?.value || '').toLowerCase().trim();
  if (searchVal) {
    rows = rows.filter(r => {
      return Object.values(r).some(val => String(val || '').toLowerCase().includes(searchVal));
    });
  }
  
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td class="p-6 text-center text-on-surface-variant italic">No matching rows found for filter: "' + searchVal + '"</td></tr>';
    return;
  }
  
  const colSet = new Set();
  rows.forEach(r => Object.keys(r).forEach(k => colSet.add(k)));
  const cols = Array.from(colSet);
  
  theadTr.innerHTML = cols.map(c => `<th class="p-3 whitespace-nowrap bg-surface-container font-bold text-primary">${c}</th>`).join('');
  
  const displayRows = rows.slice(0, 1000);
  tbody.innerHTML = displayRows.map(r => {
    return `<tr class="hover:bg-primary/5 transition-colors">` + cols.map(c => {
      const val = r[c] !== undefined && r[c] !== null ? String(r[c]) : '';
      let formattedVal = val;
      if (val.includes('⚠️ MALICIOUS')) {
        formattedVal = `<span class="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/40 rounded font-bold">${val}</span>`;
      } else if (val.includes('CLEAN')) {
        formattedVal = `<span class="text-green-400 font-semibold">${val}</span>`;
      } else if (val.includes('AbuseIPDB')) {
        formattedVal = `<span class="text-amber-400 font-semibold">${val}</span>`;
      }
      return `<td class="p-3 whitespace-nowrap border-r border-outline-variant/20">${formattedVal}</td>`;
    }).join('') + `</tr>`;
  }).join('');
  
  if (rows.length > 1000) {
    tbody.innerHTML += `<tr><td colspan="${cols.length}" class="p-3 text-center bg-amber-500/10 text-amber-500 font-bold">Showing first 1,000 rows of ${rows.length.toLocaleString()} matching rows. Refine your search query to see specific entries.</td></tr>`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const dbSelect = document.getElementById('ram-db-select');
  if (dbSelect) {
    dbSelect.addEventListener('change', () => loadRamDatabase(dbSelect.value));
  }
  
  const runSelect = document.getElementById('ram-db-run-select');
  if (runSelect) {
    runSelect.addEventListener('change', () => {
      currentRamDbRunIndex = parseInt(runSelect.value, 10);
      renderRamDbTable();
      updateRamDbMetadataBanner();
    });
  }
  
  const searchInput = document.getElementById('ram-db-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => renderRamDbTable());
  }
  
  const btnRefresh = document.getElementById('btn-refresh-ram-db');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', refreshRamDbList);
  }
  
  const btnBrowseDb = document.getElementById('btn-browse-ram-db');
  if (btnBrowseDb) {
    btnBrowseDb.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'json' });
        if (file) {
          loadRamDatabase(file);
        }
      } catch (err) {
        console.error('Failed to open file dialog:', err);
      }
    });
  }

  // Create Case Modal Handlers
  const btnShowCreateCase = document.getElementById('btn-show-create-case-modal');
  const modalCreateCase = document.getElementById('create-case-modal');
  const btnCloseCreateCase = document.getElementById('btn-close-create-case-modal');
  const btnCancelCreateCase = document.getElementById('btn-cancel-create-case');
  const btnBrowseCaseRoot = document.getElementById('btn-browse-case-root');
  const formCreateCase = document.getElementById('form-create-case');

  if (btnShowCreateCase && modalCreateCase) {
    btnShowCreateCase.addEventListener('click', () => modalCreateCase.classList.remove('hidden'));
  }
  const hideCreateCaseModal = () => {
    if (modalCreateCase) modalCreateCase.classList.add('hidden');
    if (formCreateCase) formCreateCase.reset();
  };
  if (btnCloseCreateCase) btnCloseCreateCase.addEventListener('click', hideCreateCaseModal);
  if (btnCancelCreateCase) btnCancelCreateCase.addEventListener('click', hideCreateCaseModal);

  if (btnBrowseCaseRoot) {
    btnBrowseCaseRoot.addEventListener('click', async () => {
      try {
        const folder = await invoke('browse_folder');
        if (folder) {
          const inp = document.getElementById('new-case-root-path');
          if (inp) inp.value = folder;
        }
      } catch (err) {
        console.error('Failed to browse directory:', err);
      }
    });
  }

  if (formCreateCase) {
    formCreateCase.addEventListener('submit', async (e) => {
      e.preventDefault();
      const caseNumber = document.getElementById('new-case-number').value.trim();
      const caseName = document.getElementById('new-case-name').value.trim();
      const examinerName = document.getElementById('new-case-examiner').value.trim();
      const rootPath = document.getElementById('new-case-root-path').value.trim();
      const notes = document.getElementById('new-case-notes').value.trim();

      if (!caseNumber || !caseName || !examinerName || !rootPath) {
        alert('Please fill out all required fields.');
        return;
      }

      try {
        logMessage('SYSTEM', `Creating unified forensic case folder for ${caseNumber} at ${rootPath}...`);
        const caseId = await invoke('create_case_container', {
          caseNumber,
          caseName,
          examinerName,
          notes,
          rootPath
        });
        logMessage('SYSTEM', `Case ${caseNumber} initialized successfully! Subdirectories and manifest generated.`);
        hideCreateCaseModal();
        await loadCases();
        if (caseId) {
          selectCase(caseId);
          setActiveWorkspaceCase(caseNumber, caseId);
        }
      } catch (err) {
        logMessage('ERROR', `Failed to initialize case folder: ` + err);
        alert('Error creating case folder structure: ' + err);
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // GLOBAL SETTINGS & API CONFIGURATION HANDLERS
  // ═══════════════════════════════════════════════════════════════
  const btnSettings = document.getElementById('btn-settings');
  const modalSettings = document.getElementById('settings-modal');
  const btnCloseSettings = document.getElementById('btn-close-settings-modal');
  const btnCancelSettings = document.getElementById('btn-cancel-settings');
  const btnResetSettings = document.getElementById('btn-reset-settings');
  const btnBrowseSettingsRoot = document.getElementById('btn-browse-settings-case-root');
  const formSettings = document.getElementById('form-settings');

  const syncSettingsToUI = () => {
    // 1. External API keys
    const vtKey = localStorage.getItem('OpenForensic-vt-key') || '';
    const abuseIpKey = localStorage.getItem('OpenForensic-abuseip-key') || '';
    const mbKey = localStorage.getItem('OpenForensic-mb-key') || '';
    const siemEndpoint = localStorage.getItem('OpenForensic-siem-endpoint') || '';
    const siemToken = localStorage.getItem('OpenForensic-siem-token') || '';

    const ramKeyVt = document.getElementById('ram-key-vt');
    const ramKeyAbuseIp = document.getElementById('ram-key-abuseip');
    const siemEndpointInp = document.getElementById('siem-endpoint');
    const siemTokenInp = document.getElementById('siem-token');

    if (ramKeyVt && vtKey) ramKeyVt.value = vtKey;
    if (ramKeyAbuseIp && abuseIpKey) ramKeyAbuseIp.value = abuseIpKey;
    if (siemEndpointInp && siemEndpoint) siemEndpointInp.value = siemEndpoint;
    if (siemTokenInp && siemToken) siemTokenInp.value = siemToken;

    // 2. Application & Engine Defaults
    const defaultCaseRoot = localStorage.getItem('OpenForensic-default-case-root') || '';
    const newCaseRootInp = document.getElementById('new-case-root-path');
    if (newCaseRootInp && defaultCaseRoot && !newCaseRootInp.value) {
      newCaseRootInp.value = defaultCaseRoot;
    }

    const defaultVolEngine = localStorage.getItem('OpenForensic-default-vol-engine') || '';
    const ramVolPathInp = document.getElementById('ram-vol-path');
    if (ramVolPathInp && defaultVolEngine) {
      ramVolPathInp.value = defaultVolEngine;
    }

    const defaultHashAlgo = localStorage.getItem('OpenForensic-default-hash-algo');
    const hashSelect = document.getElementById('select-hash-algo');
    if (hashSelect && defaultHashAlgo) {
      hashSelect.value = defaultHashAlgo;
    }

    const defaultBlockSize = localStorage.getItem('OpenForensic-default-block-size');
    const blockSelect = document.getElementById('select-block-size');
    if (blockSelect && defaultBlockSize) {
      blockSelect.value = defaultBlockSize;
    }

    const defaultMountRO = localStorage.getItem('OpenForensic-default-mount-readonly');
    const mountRoCheckbox = document.getElementById('mount-readonly');
    if (mountRoCheckbox && defaultMountRO !== null) {
      mountRoCheckbox.checked = defaultMountRO === 'true';
    }
  };

  const loadSettingsIntoModal = () => {
    const elVt = document.getElementById('settings-key-vt');
    const elAbuse = document.getElementById('settings-key-abuseip');
    const elMb = document.getElementById('settings-key-mb');
    const elSiemEnd = document.getElementById('settings-siem-endpoint');
    const elSiemTok = document.getElementById('settings-siem-token');
    const elCaseRoot = document.getElementById('settings-default-case-root');
    const elVolEng = document.getElementById('settings-default-vol-engine');
    const elHash = document.getElementById('settings-default-hash-algo');
    const elBlock = document.getElementById('settings-default-block-size');
    const elFormat = document.getElementById('settings-default-export-format');
    const elMountRo = document.getElementById('settings-default-mount-readonly');

    if (elVt) elVt.value = localStorage.getItem('OpenForensic-vt-key') || '';
    if (elAbuse) elAbuse.value = localStorage.getItem('OpenForensic-abuseip-key') || '';
    if (elMb) elMb.value = localStorage.getItem('OpenForensic-mb-key') || '';
    if (elSiemEnd) elSiemEnd.value = localStorage.getItem('OpenForensic-siem-endpoint') || '';
    if (elSiemTok) elSiemTok.value = localStorage.getItem('OpenForensic-siem-token') || '';
    if (elCaseRoot) elCaseRoot.value = localStorage.getItem('OpenForensic-default-case-root') || '';
    if (elVolEng) elVolEng.value = localStorage.getItem('OpenForensic-default-vol-engine') || 'Built-in Native Rust Volatility Engine (Fast)';
    if (elHash) elHash.value = localStorage.getItem('OpenForensic-default-hash-algo') || 'SHA-256';
    if (elBlock) elBlock.value = localStorage.getItem('OpenForensic-default-block-size') || '1048576';
    if (elFormat) elFormat.value = localStorage.getItem('OpenForensic-default-export-format') || 'JSON';
    if (elMountRo) elMountRo.checked = (localStorage.getItem('OpenForensic-default-mount-readonly') !== 'false');
  };

  const hideSettingsModal = () => {
    if (modalSettings) modalSettings.classList.add('hidden');
  };

  if (btnSettings && modalSettings) {
    btnSettings.addEventListener('click', () => {
      loadSettingsIntoModal();
      modalSettings.classList.remove('hidden');
    });
  }

  if (btnCloseSettings) btnCloseSettings.addEventListener('click', hideSettingsModal);
  if (btnCancelSettings) btnCancelSettings.addEventListener('click', hideSettingsModal);

  if (btnBrowseSettingsRoot) {
    btnBrowseSettingsRoot.addEventListener('click', async () => {
      try {
        const folder = await invoke('browse_folder');
        if (folder) {
          const inp = document.getElementById('settings-default-case-root');
          if (inp) inp.value = folder;
        }
      } catch (err) {
        console.error('Failed to browse settings directory:', err);
      }
    });
  }

  if (btnResetSettings) {
    btnResetSettings.addEventListener('click', () => {
      const keys = [
        'OpenForensic-vt-key', 'OpenForensic-abuseip-key', 'OpenForensic-mb-key',
        'OpenForensic-siem-endpoint', 'OpenForensic-siem-token',
        'OpenForensic-default-case-root', 'OpenForensic-default-vol-engine',
        'OpenForensic-default-hash-algo', 'OpenForensic-default-block-size',
        'OpenForensic-default-export-format', 'OpenForensic-default-mount-readonly'
      ];
      keys.forEach(k => localStorage.removeItem(k));
      loadSettingsIntoModal();
      syncSettingsToUI();
      logMessage('SYSTEM', '[SETTINGS] Reset global API keys and defaults.');
    });
  }

  if (formSettings) {
    formSettings.addEventListener('submit', (e) => {
      e.preventDefault();
      const vt = document.getElementById('settings-key-vt')?.value.trim() || '';
      const abuseIp = document.getElementById('settings-key-abuseip')?.value.trim() || '';
      const mb = document.getElementById('settings-key-mb')?.value.trim() || '';
      const siemEnd = document.getElementById('settings-siem-endpoint')?.value.trim() || '';
      const siemTok = document.getElementById('settings-siem-token')?.value.trim() || '';
      const caseRoot = document.getElementById('settings-default-case-root')?.value.trim() || '';
      const volEng = document.getElementById('settings-default-vol-engine')?.value || 'Built-in Native Rust Volatility Engine (Fast)';
      const hashAlgo = document.getElementById('settings-default-hash-algo')?.value || 'SHA-256';
      const blockSize = document.getElementById('settings-default-block-size')?.value || '1048576';
      const exportFormat = document.getElementById('settings-default-export-format')?.value || 'JSON';
      const mountRo = document.getElementById('settings-default-mount-readonly')?.checked !== false;

      localStorage.setItem('OpenForensic-vt-key', vt);
      localStorage.setItem('OpenForensic-abuseip-key', abuseIp);
      localStorage.setItem('OpenForensic-mb-key', mb);
      localStorage.setItem('OpenForensic-siem-endpoint', siemEnd);
      localStorage.setItem('OpenForensic-siem-token', siemTok);
      localStorage.setItem('OpenForensic-default-case-root', caseRoot);
      localStorage.setItem('OpenForensic-default-vol-engine', volEng);
      localStorage.setItem('OpenForensic-default-hash-algo', hashAlgo);
      localStorage.setItem('OpenForensic-default-block-size', blockSize);
      localStorage.setItem('OpenForensic-default-export-format', exportFormat);
      localStorage.setItem('OpenForensic-default-mount-readonly', String(mountRo));

      syncSettingsToUI();
      hideSettingsModal();
      logMessage('SUCCESS', '[SETTINGS] Saved external API keys and system defaults successfully.');
    });
  }

  listen('carving-progress', (event) => {
    const { bytes_processed, total_bytes, percentage, files_found } = event.payload;
    const btn = document.getElementById('btn-run-parallel-carver');
    if (btn) {
      btn.textContent = `Carving... ${percentage.toFixed(1)}% (${files_found} files)`;
    }
  });

  // Initialize saved settings on app load
  syncSettingsToUI();
});

window.runCarverBenchmarkUI = async function() {
  const resultDiv = document.getElementById('carver-benchmark-result');
  if (!resultDiv) return;
  resultDiv.classList.remove('hidden');
  resultDiv.innerHTML = '<div class="flex items-center gap-2"><span>Running synthetic multi-threaded carving benchmark (Single-Threaded vs Rayon Parallel)...</span></div>';

  try {
    const res = await invoke('benchmark_data_recovery_carving', { sampleSizeMb: 32 });
    resultDiv.innerHTML = `
      <div class="font-bold text-emerald-300 mb-1">✅ Multi-Threaded Carver Benchmark Complete (32 MB synthetic test image):</div>
      <div>• Single-Threaded Baseline: <span class="text-white font-semibold">${res.single_thread_duration_ms} ms</span></div>
      <div>• Rayon Parallel Engine: <span class="text-white font-semibold">${res.multi_thread_duration_ms} ms</span></div>
      <div>• Speedup Factor: <span class="text-emerald-400 font-bold">${res.speedup_factor.toFixed(2)}x speedup</span> across CPU cores</div>
      <div>• Throughput: <span class="text-white font-semibold">${res.throughput_mb_per_sec.toFixed(1)} MB/s</span></div>
      <div>• Recovered Objects: <span class="text-white font-semibold">${res.files_carved} files</span> carved</div>
    `;
  } catch (e) {
    resultDiv.innerHTML = `<div class="text-red-400">Benchmark error: ${e}</div>`;
  }
};

window.runParallelCarverUI = async function() {
  const imagePath = document.getElementById('carve-image-path')?.value.trim();
  const outDir = document.getElementById('carve-out-dir')?.value.trim();
  const dbPath = document.getElementById('triage-db-path')?.value.trim();
  if (!imagePath || !outDir) {
    alert('Please specify both the target Image/Raw dump path and output folder.');
    return;
  }
  try {
    const btn = document.getElementById('btn-run-parallel-carver');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Carving...';
    }
    const records = await invoke('run_data_recovery_carving', {
      imagePath,
      outDir,
      dbPath: dbPath || null
    });
    alert(`Carving Complete! Recovered ${records.length} files into ${outDir}.`);
  } catch (e) {
    alert(`Carving failed: ${e}`);
  } finally {
    const btn = document.getElementById('btn-run-parallel-carver');
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span class="material-symbols-outlined text-[18px]">play_arrow</span>Start Rayon Carver';
    }
  }
};


