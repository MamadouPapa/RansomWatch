"""Default thresholds and static catalogues used by RansomWatch.

Every tunable value lives here so that nothing in the detection logic is a
magic number. CLI flags in ransomwatch.py override the defaults.
"""

# --- Polling -----------------------------------------------------------------
DEFAULT_POLL_INTERVAL_S = 1.0

# --- RW-001: burst of file creations / modifications ---------------------------
DEFAULT_BURST_THRESHOLD = 20          # events inside the window
DEFAULT_BURST_WINDOW_S = 10.0         # sliding window length
BURST_SAMPLE_PATHS = 5                # paths quoted in the alert details

# --- RW-002: entropy of written content ----------------------------------------
DEFAULT_ENTROPY_THRESHOLD = 7.5       # bits per byte (max is 8.0)
DEFAULT_ENTROPY_MIN_SIZE = 1024       # smaller samples cannot reach ~8 bits/byte
DEFAULT_ENTROPY_SAMPLE_BYTES = 65536  # only the head of a file is read
DEFAULT_ENTROPY_JUMP = 1.0            # min increase vs baseline for a known file
BITS_PER_BYTE_MAX = 8.0
BYTE_VALUES = 256

# Formats that are legitimately high-entropy: never scored by RW-002.
NATURALLY_COMPRESSED_EXTENSIONS = frozenset({
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".mkv",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".jar", ".whl",
})

# --- RW-004: archive creation followed by deletions ----------------------------
ARCHIVE_EXTENSIONS = frozenset({
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
})
DEFAULT_ARCHIVE_WINDOW_S = 30.0
DEFAULT_ARCHIVE_DELETE_THRESHOLD = 5

# --- RW-005: original replaced by a sibling with an extra extension -----------
DEFAULT_SWAP_THRESHOLD = 3
DEFAULT_SWAP_WINDOW_S = 30.0
SWAP_MAX_SUFFIX_LEN = 12              # ".enc", ".locked", ".crypted"...

# --- Severities ----------------------------------------------------------------
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
SEVERITY_ORDER = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)
DEFAULT_RESPOND_MIN_SEVERITY = SEVERITY_HIGH

# --- Rule catalogue: id -> (name, severity, MITRE id, MITRE name) --------------
RULES = {
    "RW-001": ("File write burst", SEVERITY_HIGH,
               "T1486", "Data Encrypted for Impact"),
    "RW-002": ("High-entropy content written", SEVERITY_HIGH,
               "T1486", "Data Encrypted for Impact"),
    "RW-003": ("Ransom note filename", SEVERITY_CRITICAL,
               "T1486", "Data Encrypted for Impact"),
    "RW-004": ("Archive created then originals deleted", SEVERITY_HIGH,
               "T1560.002", "Archive Collected Data: Archive via Library"),
    "RW-005": ("Originals replaced by renamed copies", SEVERITY_CRITICAL,
               "T1486", "Data Encrypted for Impact"),
}

# --- Response --------------------------------------------------------------------
DEFAULT_INCIDENT_FILE = "ransomwatch-incident.jsonl"
PROC_ROOT = "/proc"
PROTECTED_PID_MAX = 1                 # never signal PID 0/1
