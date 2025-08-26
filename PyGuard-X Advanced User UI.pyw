import os
import sys
import re
import json
import time
import base64
import hashlib
import shutil
import threading
import queue
import fnmatch
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__) or ".", ".pyguardian"))
os.makedirs(APP_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
SIG_PATH = os.path.join(APP_DIR, "signatures.json")
QUAR_META_PATH = os.path.join(APP_DIR, "quarantine.json")
LOG_PATH = os.path.join(APP_DIR, "events.log")
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "heuristics_enabled": True,
    "max_scan_bytes": 1024 * 1024,
    "text_sniff_bytes": 4096,
    "exclude_dirs": [QUARANTINE_DIR],
    "whitelist": [],
    "realtime_paths": [],
    "scheduler_enabled": False,
    "scheduler_interval_minutes": 60,
    "scheduler_last_run": None,
    "ui": {"theme": "dark"},
}

DEFAULT_SIGNATURES = {
    "EICAR_Test_File": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
}

HEURISTIC_PATTERNS = [
    ("Suspicious_eval_exec_py", re.compile(rb"\b(eval|exec)\s*\(")),
    ("Base64_then_exec", re.compile(rb"(base64\.b64decode\(.*\))", re.DOTALL)),
    ("Powershell_EncodedCommand", re.compile(rb"powershell(?:\.exe)?\s+-enc(?:odedcommand)?\b", re.IGNORECASE)),
    ("Curl_or_Wget_execute", re.compile(rb"\b(curl|wget)\b.*\b(sh|bash|powershell)\b", re.IGNORECASE)),
    ("Obfuscated_JS_eval", re.compile(rb"\beval\((atob|unescape|Function)", re.IGNORECASE)),
]

class Storage:
    def __init__(self):
        self.config = None
        self.signatures = None
        self.sig_hash_to_name = {}
        self.quarantine_meta = {}
        self.load_all()

    def load_all(self):
        self.config = self._load_json(CONFIG_PATH, DEFAULT_CONFIG)
        self.signatures = self._load_json(SIG_PATH, DEFAULT_SIGNATURES)
        self.sig_hash_to_name = {h: n for n, h in self.signatures.items()}
        self.quarantine_meta = self._load_json(QUAR_META_PATH, {})

    def save_config(self):
        self._save_json(CONFIG_PATH, self.config)

    def save_signatures(self):
        self._save_json(SIG_PATH, self.signatures)
        self.sig_hash_to_name = {h: n for n, h in self.signatures.items()}

    def save_quarantine(self):
        self._save_json(QUAR_META_PATH, self.quarantine_meta)

    def _load_json(self, path, default):
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return json.loads(json.dumps(default))

    def _save_json(self, path, data):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)

storage = Storage()

def append_log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    return line

def sha256_file(path, block_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def is_probably_text(data: bytes) -> bool:
    try:
        s = data.decode("utf-8")
        printable = sum(1 for ch in s if ch.isprintable() or ch.isspace())
        return printable / max(1, len(s)) > 0.85
    except UnicodeDecodeError:
        return False

def scan_buffer_for_heuristics(buf: bytes):
    findings = []
    for name, rx in HEURISTIC_PATTERNS:
        m = rx.search(buf)
        if m:
            snippet = buf[m.start():m.end()]
            findings.append((f"Heuristic:{name}", repr(snippet[:160])))
    return findings

def is_whitelisted(path):
    wl = storage.config.get("whitelist", [])
    for item in wl:
        try:
            if os.path.abspath(path).startswith(os.path.abspath(item)):
                return True
        except Exception:
            pass
    return False

def is_excluded_dir(base):
    for d in storage.config.get("exclude_dirs", []):
        if os.path.abspath(base).startswith(os.path.abspath(d)):
            return True
    return False

def scan_file(path):
    results = []
    try:
        if is_whitelisted(path):
            return []
        digest = sha256_file(path)
        if digest in storage.sig_hash_to_name:
            nm = storage.sig_hash_to_name[digest]
            results.append(("Signature:" + nm, "high", digest, None))
        if storage.config.get("heuristics_enabled", True):
            tsniff = int(storage.config.get("text_sniff_bytes", 4096))
            cap = int(storage.config.get("max_scan_bytes", 1024 * 1024))
            with open(path, "rb") as f:
                sniff = f.read(tsniff)
                if is_probably_text(sniff):
                    buf = sniff + f.read(max(0, cap - len(sniff)))
                    for reason, evidence in scan_buffer_for_heuristics(buf):
                        results.append((reason, "medium", None, evidence))
    except Exception:
        return results
    return results

def iter_files(root):
    for base, dirs, files in os.walk(root):
        if is_excluded_dir(base):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not is_excluded_dir(os.path.join(base, d))]
        for fname in files:
            path = os.path.join(base, fname)
            yield path

def quarantine_move(path, reason):
    try:
        digest = None
        try:
            digest = sha256_file(path)
        except Exception:
            pass
        base = os.path.basename(path)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = os.path.join(QUARANTINE_DIR, f"{ts}__{base}")
        shutil.move(path, dest)
        storage.quarantine_meta[dest] = {
            "original_path": path,
            "reason": reason,
            "timestamp": ts,
            "sha256": digest,
            "size": os.path.getsize(dest) if os.path.exists(dest) else None,
        }
        storage.save_quarantine()
        append_log(f"Quarantined: {path} -> {dest} ({reason})")
        return dest
    except Exception as e:
        append_log(f"Quarantine failed: {path} ({e})")
        return None

def quarantine_restore(quar_path):
    meta = storage.quarantine_meta.get(quar_path)
    if not meta:
        return False, "No metadata"
    orig = meta.get("original_path", "")
    try:
        os.makedirs(os.path.dirname(orig) or ".", exist_ok=True)
        shutil.move(quar_path, orig)
        del storage.quarantine_meta[quar_path]
        storage.save_quarantine()
        append_log(f"Restored: {quar_path} -> {orig}")
        return True, orig
    except Exception as e:
        return False, str(e)

def quarantine_delete(quar_path):
    try:
        os.remove(quar_path)
    except Exception:
        pass
    if quar_path in storage.quarantine_meta:
        del storage.quarantine_meta[quar_path]
        storage.save_quarantine()
    append_log(f"Deleted from quarantine: {quar_path}")
    return True

class TaskThread(threading.Thread):
    def __init__(self, target, args=()):
        super().__init__(daemon=True)
        self.target = target
        self.args = args
        self.exc = None

    def run(self):
        try:
            self.target(*self.args)
        except Exception as e:
            self.exc = e

class Scheduler:
    def __init__(self, app):
        self.app = app
        self._stop = threading.Event()
        self.thread = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self._stop.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            cfg = storage.config
            if cfg.get("scheduler_enabled", False):
                last = cfg.get("scheduler_last_run")
                interval = int(cfg.get("scheduler_interval_minutes", 60))
                now = time.time()
                due = True
                if last is not None:
                    due = (now - last) >= (interval * 60)
                if due:
                    storage.config["scheduler_last_run"] = now
                    storage.save_config()
                    try:
                        targets = cfg.get("realtime_paths", []) or [os.path.expanduser("~")]
                        for p in targets:
                            if os.path.exists(p):
                                self.app.enqueue_scan(p, label=f"Scheduled Scan: {p}", quarantine=True)
                    except Exception:
                        pass
            for _ in range(30):
                if self._stop.is_set():
                    break
                time.sleep(1)

class RealTimeHandler(FileSystemEventHandler):
    def __init__(self, app, path):
        self.app = app
        self.path = path

    def on_created(self, event):
        if event.is_directory:
            return
        self.app.enqueue_single_file_scan(event.src_path, label="Real-Time", quarantine=True)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.app.enqueue_single_file_scan(event.src_path, label="Real-Time", quarantine=True)

class RealTimeManager:
    def __init__(self, app):
        self.app = app
        self.observer = None
        self.paths = set()

    def start(self):
        if not WATCHDOG_AVAILABLE:
            return False, "watchdog not installed"
        if self.observer and self.observer.is_alive():
            return True, "already running"
        self.observer = Observer()
        for p in storage.config.get("realtime_paths", []):
            if os.path.isdir(p):
                self.paths.add(p)
        for p in list(self.paths):
            try:
                self.observer.schedule(RealTimeHandler(self.app, p), path=p, recursive=True)
            except Exception:
                pass
        self.observer.start()
        append_log("Real-time protection started")
        return True, "started"

    def stop(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except Exception:
                pass
            self.observer = None
            append_log("Real-time protection stopped")

    def add_path(self, p):
        p = os.path.abspath(p)
        if p not in self.paths:
            self.paths.add(p)
            cfg = storage.config
            if p not in cfg["realtime_paths"]:
                cfg["realtime_paths"].append(p)
                storage.save_config()
        if self.observer and self.observer.is_alive():
            try:
                self.observer.schedule(RealTimeHandler(self.app, p), path=p, recursive=True)
            except Exception:
                pass

    def remove_path(self, p):
        p = os.path.abspath(p)
        if p in self.paths:
            self.paths.remove(p)
        cfg = storage.config
        if p in cfg["realtime_paths"]:
            cfg["realtime_paths"].remove(p)
            storage.save_config()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyGuardian X")
        self.geometry("1080x720")
        self.minsize(960, 640)
        self.style = ttk.Style()
        self._apply_theme(storage.config.get("ui", {}).get("theme", "dark"))
        self.event_queue = queue.Queue()
        self.scan_queue = queue.Queue()
        self.current_scans = 0
        self.total_findings = 0
        self.last_scan_time = None
        self.realtime = RealTimeManager(self)
        self.scheduler = Scheduler(self)
        self._build_ui()
        self._load_quarantine_tab()
        self._load_realtime_tab()
        self._load_settings_tab()
        self._load_logs_tab()
        self.after(100, self._drain_event_queue)
        self.after(150, self._drain_scan_queue)
        if storage.config.get("scheduler_enabled", False):
            self.scheduler.start()

    def _apply_theme(self, mode):
        bg = "#0f1117" if mode == "dark" else "#f5f5f5"
        fg = "#e5e7eb" if mode == "dark" else "#111827"
        acc = "#2563eb"
        self.configure(bg=bg)
        self.style.theme_use("default")
        self.style.configure(".", background=bg, foreground=fg, fieldbackground=bg)
        self.style.configure("TButton", padding=8, relief="flat")
        self.style.map("TButton", background=[("active", acc)], foreground=[("active", "#ffffff")])
        self.style.configure("TNotebook.Tab", padding=(12, 8))
        self.style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, rowheight=26)
        self.style.configure("Vertical.TScrollbar", background=bg)
        self.style.configure("Horizontal.TScrollbar", background=bg)

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)
        self.status_lbl = ttk.Label(top, text="Status: Idle")
        self.status_lbl.pack(side="left")
        self.prog = ttk.Progressbar(top, mode="determinate", length=240)
        self.prog.pack(side="left", padx=10)
        self.prog["value"] = 0
        right = ttk.Frame(top)
        right.pack(side="right")
        ttk.Button(right, text="Export Report", command=self.export_report).pack(side="left", padx=5)
        ttk.Button(right, text="Open Data Folder", command=lambda: self._open_folder(APP_DIR)).pack(side="left", padx=5)
        ttk.Button(right, text="About", command=self._about).pack(side="left", padx=5)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=10)

        self.tab_dashboard = ttk.Frame(self.nb)
        self.tab_scan = ttk.Frame(self.nb)
        self.tab_realtime = ttk.Frame(self.nb)
        self.tab_quarantine = ttk.Frame(self.nb)
        self.tab_logs = ttk.Frame(self.nb)
        self.tab_settings = ttk.Frame(self.nb)
        self.tab_tools = ttk.Frame(self.nb)

        self.nb.add(self.tab_dashboard, text="Dashboard")
        self.nb.add(self.tab_scan, text="Scan")
        self.nb.add(self.tab_realtime, text="Real-Time")
        self.nb.add(self.tab_quarantine, text="Quarantine")
        self.nb.add(self.tab_logs, text="Logs")
        self.nb.add(self.tab_settings, text="Settings")
        self.nb.add(self.tab_tools, text="Tools")

        self._build_dashboard()
        self._build_scan_tab()
        self._build_tools_tab()

    def _build_dashboard(self):
        frame = self.tab_dashboard
        t = ttk.Label(frame, text="PyGuardian X", font=("Segoe UI", 24, "bold"))
        t.pack(pady=16)
        grid = ttk.Frame(frame)
        grid.pack(pady=6)
        self.dash_status = ttk.Label(grid, text="Protection: Stopped", font=("Segoe UI", 12))
        self.dash_last_scan = ttk.Label(grid, text="Last Scan: —", font=("Segoe UI", 12))
        self.dash_findings = ttk.Label(grid, text="Total Findings (session): 0", font=("Segoe UI", 12))
        self.dash_status.grid(row=0, column=0, padx=20, pady=8, sticky="w")
        self.dash_last_scan.grid(row=0, column=1, padx=20, pady=8, sticky="w")
        self.dash_findings.grid(row=0, column=2, padx=20, pady=8, sticky="w")
        btns = ttk.Frame(frame)
        btns.pack(pady=12)
        ttk.Button(btns, text="Start Real-Time", command=self._start_realtime).grid(row=0, column=0, padx=8)
        ttk.Button(btns, text="Stop Real-Time", command=self._stop_realtime).grid(row=0, column=1, padx=8)
        ttk.Button(btns, text="Quick Scan (Home)", command=self._quick_scan).grid(row=0, column=2, padx=8)

    def _build_scan_tab(self):
        frame = self.tab_scan
        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=6)
        ttk.Button(controls, text="Scan File", command=self._scan_file_dialog).pack(side="left", padx=5)
        ttk.Button(controls, text="Scan Folder", command=self._scan_folder_dialog).pack(side="left", padx=5)
        self.quarantine_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Auto-quarantine", variable=self.quarantine_var).pack(side="left", padx=10)
        ttk.Label(controls, text="Include patterns (comma):").pack(side="left", padx=(20, 5))
        self.include_entry = ttk.Entry(controls, width=24)
        self.include_entry.pack(side="left")
        ttk.Label(controls, text="Exclude patterns (comma):").pack(side="left", padx=(20, 5))
        self.exclude_entry = ttk.Entry(controls, width=24)
        self.exclude_entry.pack(side="left")
        self.tree = ttk.Treeview(frame, columns=("path", "reason", "severity", "sha256", "action"), show="headings", selectmode="extended")
        for col, w in [("path", 520), ("reason", 240), ("severity", 100), ("sha256", 320), ("action", 120)]:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=w, stretch=True)
        ysb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(0, 0), pady=4)
        ysb.pack(side="left", fill="y")
        actions = ttk.Frame(frame)
        actions.pack(side="right", fill="y", padx=6)
        ttk.Button(actions, text="Quarantine Selected", command=self._quarantine_selected).pack(fill="x", pady=4)
        ttk.Button(actions, text="Copy Paths", command=self._copy_selected_paths).pack(fill="x", pady=4)
        ttk.Button(actions, text="Clear Results", command=lambda: self.tree.delete(*self.tree.get_children())).pack(fill="x", pady=4)

    def _build_tools_tab(self):
        frame = self.tab_tools
        box = ttk.Frame(frame)
        box.pack(fill="x", pady=8, padx=8)
        ttk.Label(box, text="Hash Calculator").grid(row=0, column=0, sticky="w")
        ttk.Button(box, text="Choose File", command=self._hash_dialog).grid(row=0, column=1, padx=8)
        self.hash_out = ttk.Entry(box, width=96)
        self.hash_out.grid(row=0, column=2, padx=8)
        sigbox = ttk.LabelFrame(frame, text="Signatures")
        sigbox.pack(fill="x", pady=8, padx=8)
        ttk.Button(sigbox, text="Import Signatures (JSON)", command=self._import_sigs).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(sigbox, text="Export Signatures (JSON)", command=self._export_sigs).grid(row=0, column=1, padx=6, pady=6)
        ttk.Label(sigbox, text="Add Signature (name=hash)").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        self.sig_add_entry = ttk.Entry(sigbox, width=80)
        self.sig_add_entry.grid(row=1, column=1, padx=6, pady=6, sticky="w")
        ttk.Button(sigbox, text="Add", command=self._add_sig).grid(row=1, column=2, padx=6, pady=6)
        eic = ttk.LabelFrame(frame, text="Test Tools")
        eic.pack(fill="x", pady=8, padx=8)
        ttk.Button(eic, text="Generate EICAR Test File", command=self._gen_eicar).grid(row=0, column=0, padx=6, pady=6)

    def _load_realtime_tab(self):
        frame = self.tab_realtime
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=8, padx=8)
        ttk.Button(top, text="Add Folder", command=self._rt_add_path).pack(side="left", padx=6)
        ttk.Button(top, text="Remove Selected", command=self._rt_remove_selected).pack(side="left", padx=6)
        ttk.Button(top, text="Start", command=self._start_realtime).pack(side="left", padx=6)
        ttk.Button(top, text="Stop", command=self._stop_realtime).pack(side="left", padx=6)
        self.rt_status = ttk.Label(top, text=f"Watchdog: {'OK' if WATCHDOG_AVAILABLE else 'Not Installed'}")
        self.rt_status.pack(side="right")
        self.rt_list = ttk.Treeview(frame, columns=("path",), show="headings")
        self.rt_list.heading("path", text="Monitored Folders")
        self.rt_list.column("path", width=880, stretch=True)
        self.rt_list.pack(fill="both", expand=True, padx=8, pady=6)
        for p in storage.config.get("realtime_paths", []):
            self.rt_list.insert("", "end", values=(p,))

    def _load_quarantine_tab(self):
        frame = self.tab_quarantine
        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=6, padx=8)
        ttk.Button(controls, text="Restore Selected", command=self._q_restore).pack(side="left", padx=6)
        ttk.Button(controls, text="Delete Selected", command=self._q_delete).pack(side="left", padx=6)
        ttk.Button(controls, text="Open Quarantine Folder", command=lambda: self._open_folder(QUARANTINE_DIR)).pack(side="left", padx=6)
        self.q_tree = ttk.Treeview(frame, columns=("quar", "original", "reason", "time", "sha256", "size"), show="headings")
        for col, w in [("quar", 380), ("original", 420), ("reason", 200), ("time", 140), ("sha256", 360), ("size", 100)]:
            self.q_tree.heading(col, text=col.capitalize())
            self.q_tree.column(col, width=w, stretch=True)
        ysb = ttk.Scrollbar(frame, orient="vertical", command=self.q_tree.yview)
        self.q_tree.configure(yscroll=ysb.set)
        self.q_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=6)
        ysb.pack(side="left", fill="y", pady=6)
        self._refresh_quarantine_list()

    def _load_logs_tab(self):
        frame = self.tab_logs
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=6, padx=8)
        ttk.Button(top, text="Refresh", command=self._refresh_logs).pack(side="left", padx=6)
        ttk.Button(top, text="Export Logs", command=self._export_logs).pack(side="left", padx=6)
        self.log_text = ScrolledText(frame, height=26)
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)
        self._refresh_logs()

    def _load_settings_tab(self):
        frame = self.tab_settings
        left = ttk.Frame(frame)
        left.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        right = ttk.Frame(frame)
        right.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        self.heur_var = tk.BooleanVar(value=storage.config.get("heuristics_enabled", True))
        ttk.Checkbutton(left, text="Enable Heuristics", variable=self.heur_var).pack(anchor="w", pady=4)
        ttk.Label(left, text="Max Scan Bytes").pack(anchor="w")
        self.max_bytes_entry = ttk.Entry(left, width=18)
        self.max_bytes_entry.insert(0, str(storage.config.get("max_scan_bytes", 1024 * 1024)))
        self.max_bytes_entry.pack(anchor="w", pady=4)
        ttk.Label(left, text="Text Sniff Bytes").pack(anchor="w")
        self.sniff_entry = ttk.Entry(left, width=18)
        self.sniff_entry.insert(0, str(storage.config.get("text_sniff_bytes", 4096)))
        self.sniff_entry.pack(anchor="w", pady=4)
        ttk.Label(right, text="Exclude Dirs (one per line)").pack(anchor="w")
        self.excl_text = ScrolledText(right, height=8, width=48)
        self.excl_text.pack(fill="x", pady=4)
        self.excl_text.delete("1.0", "end")
        self.excl_text.insert("1.0", "\n".join(storage.config.get("exclude_dirs", [])))
        ttk.Label(right, text="Whitelist (one path per line)").pack(anchor="w")
        self.wl_text = ScrolledText(right, height=8, width=48)
        self.wl_text.pack(fill="x", pady=4)
        self.wl_text.delete("1.0", "end")
        self.wl_text.insert("1.0", "\n".join(storage.config.get("whitelist", [])))
        sched = ttk.LabelFrame(frame, text="Scheduler")
        sched.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        self.sched_var = tk.BooleanVar(value=storage.config.get("scheduler_enabled", False))
        ttk.Checkbutton(sched, text="Enable Scheduled Scans", variable=self.sched_var).pack(anchor="w", pady=4)
        ttk.Label(sched, text="Interval (minutes)").pack(anchor="w")
        self.sched_int_entry = ttk.Entry(sched, width=10)
        self.sched_int_entry.insert(0, str(storage.config.get("scheduler_interval_minutes", 60)))
        self.sched_int_entry.pack(anchor="w", pady=4)
        ttk.Button(frame, text="Save Settings", command=self._save_settings).pack(side="left", padx=16, pady=12)
        ttk.Button(frame, text="Switch Theme", command=self._switch_theme).pack(side="left", padx=8, pady=12)

    def _start_realtime(self):
        ok, msg = self.realtime.start()
        self._update_dash_status()
        if not ok:
            messagebox.showwarning("Real-Time", msg)
        else:
            self._info("Real-time protection started")

    def _stop_realtime(self):
        self.realtime.stop()
        self._update_dash_status()
        self._info("Real-time protection stopped")

    def _quick_scan(self):
        home = os.path.expanduser("~")
        if not os.path.exists(home):
            home = "."
        self.enqueue_scan(home, label="Quick Scan", quarantine=True)

    def _scan_file_dialog(self):
        path = filedialog.askopenfilename()
        if path:
            self.enqueue_scan(path, label="Manual File Scan", quarantine=self.quarantine_var.get())

    def _scan_folder_dialog(self):
        path = filedialog.askdirectory()
        if path:
            self.enqueue_scan(path, label="Manual Folder Scan", quarantine=self.quarantine_var.get())

    def enqueue_scan(self, path, label="Scan", quarantine=True):
        self.scan_queue.put(("path", path, label, quarantine, self.include_entry.get(), self.exclude_entry.get()))

    def enqueue_single_file_scan(self, path, label="Scan", quarantine=True):
        self.scan_queue.put(("file", path, label, quarantine, "", ""))

    def _drain_scan_queue(self):
        try:
            item = self.scan_queue.get_nowait()
        except queue.Empty:
            self.after(150, self._drain_scan_queue)
            return
        kind, path, label, quarantine, include_raw, exclude_raw = item
        t = TaskThread(target=self._run_scan, args=(kind, path, label, quarantine, include_raw, exclude_raw))
        t.start()
        self.after(150, self._drain_scan_queue)

    def _run_scan(self, kind, path, label, quarantine, include_raw, exclude_raw):
        self.current_scans += 1
        self._set_status(f"{label}: Running")
        self._set_progress(0)
        include = [p.strip() for p in include_raw.split(",") if p.strip()]
        exclude = [p.strip() for p in exclude_raw.split(",") if p.strip()]
        paths = []
        if kind == "file":
            if os.path.isfile(path):
                paths = [path]
        else:
            if os.path.isfile(path):
                paths = [path]
            else:
                paths = list(iter_files(path))
        total = len(paths) if kind != "file" else 1
        found_local = 0
        for idx, p in enumerate(paths, start=1):
            if exclude and any(fnmatch.fnmatch(os.path.basename(p), pat) for pat in exclude):
                self.event_queue.put(("log", append_log(f"Skipped: {p} (exclude pattern)")))
                self._emit_tree_row(p, "Skipped", "low", None, "skipped")
                continue
            if include and not any(fnmatch.fnmatch(os.path.basename(p), pat) for pat in include):
                self._emit_tree_row(p, "Skipped (not included)", "low", None, "skipped")
                continue
            try:
                results = scan_file(p)
            except Exception as e:
                self.event_queue.put(("log", append_log(f"Scan error: {p} ({e})")))
                continue
            if results:
                for reason, severity, digest, evidence in results:
                    found_local += 1
                    act = "none"
                    if quarantine:
                        dest = quarantine_move(p, reason)
                        act = f"quarantined -> {os.path.basename(dest) if dest else 'fail'}"
                    self._emit_tree_row(p, reason if not evidence else f"{reason} [{evidence[:64]}]", severity, digest, act)
            else:
                self._emit_tree_row(p, "Clean", "low", None, "none")
            self._set_progress(int((idx / max(1, total)) * 100))
        self.total_findings += found_local
        self.last_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._update_dash_status()
        self._set_status(f"{label}: Done ({found_local} detections)")
        self.current_scans -= 1

    def _emit_tree_row(self, path, reason, severity, digest, action):
        self.event_queue.put(("tree", (path, reason, severity, digest or "", action)))
        if "Signature:" in reason or "Heuristic:" in reason:
            self.event_queue.put(("log", append_log(f"Detection: {path} ({reason}) action={action}")))
        else:
            self.event_queue.put(("log", append_log(f"Scan: {path} -> {reason}")))

    def _drain_event_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "tree":
                    self.tree.insert("", "end", values=payload)
                elif kind == "log":
                    self._append_log_text(payload)
        except queue.Empty:
            pass
        self.after(120, self._drain_event_queue)

    def _append_log_text(self, line):
        try:
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
        except Exception:
            pass

    def _refresh_quarantine_list(self):
        for iid in self.q_tree.get_children():
            self.q_tree.delete(iid)
        for qp, meta in sorted(storage.quarantine_meta.items()):
            self.q_tree.insert("", "end", values=(
                qp,
                meta.get("original_path", ""),
                meta.get("reason", ""),
                meta.get("timestamp", ""),
                meta.get("sha256", "") or "",
                meta.get("size", ""),
            ))

    def _q_restore(self):
        sels = self.q_tree.selection()
        if not sels:
            return
        for s in sels:
            qp = self.q_tree.item(s, "values")[0]
            ok, msg = quarantine_restore(qp)
            if ok:
                self._info(f"Restored to {msg}")
            else:
                self._warn(f"Restore failed: {msg}")
        self._refresh_quarantine_list()

    def _q_delete(self):
        sels = self.q_tree.selection()
        if not sels:
            return
        if not messagebox.askyesno("Delete", "Permanently delete selected quarantined files?"):
            return
        for s in sels:
            qp = self.q_tree.item(s, "values")[0]
            quarantine_delete(qp)
        self._refresh_quarantine_list()

    def _refresh_logs(self):
        self.log_text.delete("1.0", "end")
        try:
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH, "r", encoding="utf-8") as f:
                    self.log_text.insert("1.0", f.read())
        except Exception:
            pass
        self.log_text.see("end")

    def _export_logs(self):
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        try:
            shutil.copyfile(LOG_PATH, path)
            self._info("Logs exported")
        except Exception as e:
            self._warn(f"Export failed: {e}")

    def export_report(self):
        items = [self.tree.item(i, "values") for i in self.tree.get_children()]
        rep = {
            "generated_at": datetime.datetime.now().isoformat(),
            "findings": [
                {"path": it[0], "reason": it[1], "severity": it[2], "sha256": it[3], "action": it[4]}
                for it in items
            ]
        }
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=2)
            self._info("Report saved")
        except Exception as e:
            self._warn(f"Save failed: {e}")

    def _save_settings(self):
        try:
            storage.config["heuristics_enabled"] = bool(self.heur_var.get())
            storage.config["max_scan_bytes"] = int(self.max_bytes_entry.get().strip())
            storage.config["text_sniff_bytes"] = int(self.sniff_entry.get().strip())
            ed = [ln.strip() for ln in self.excl_text.get("1.0", "end").splitlines() if ln.strip()]
            wl = [ln.strip() for ln in self.wl_text.get("1.0", "end").splitlines() if ln.strip()]
            storage.config["exclude_dirs"] = ed
            storage.config["whitelist"] = wl
            storage.config["scheduler_enabled"] = bool(self.sched_var.get())
            storage.config["scheduler_interval_minutes"] = int(self.sched_int_entry.get().strip())
            storage.save_config()
            if storage.config["scheduler_enabled"]:
                self.scheduler.start()
            else:
                self.scheduler.stop()
            self._info("Settings saved")
        except Exception as e:
            self._warn(f"Save failed: {e}")

    def _switch_theme(self):
        cur = storage.config.get("ui", {}).get("theme", "dark")
        nxt = "light" if cur == "dark" else "dark"
        storage.config.setdefault("ui", {})["theme"] = nxt
        storage.save_config()
        self._apply_theme(nxt)

    def _rt_add_path(self):
        p = filedialog.askdirectory()
        if not p:
            return
        self.realtime.add_path(p)
        self.rt_list.insert("", "end", values=(p,))
        self._info("Added folder to real-time monitor")

    def _rt_remove_selected(self):
        sels = self.rt_list.selection()
        for s in sels:
            p = self.rt_list.item(s, "values")[0]
            self.realtime.remove_path(p)
            self.rt_list.delete(s)
        self._info("Removed selected folders from real-time")

    def _quarantine_selected(self):
        sels = self.tree.selection()
        for s in sels:
            vals = self.tree.item(s, "values")
            p = vals[0]
            reason = vals[1]
            if os.path.exists(p):
                dest = quarantine_move(p, reason)
                self.tree.set(s, "action", f"quarantined -> {os.path.basename(dest) if dest else 'fail'}")
        self._refresh_quarantine_list()

    def _copy_selected_paths(self):
        sels = self.tree.selection()
        paths = [self.tree.item(s, "values")[0] for s in sels]
        if not paths:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(paths))
            self._info("Copied paths")
        except Exception:
            pass

    def _update_dash_status(self):
        rt = "Running" if self.realtime.observer and self.realtime.observer.is_alive() else "Stopped"
        self.dash_status.configure(text=f"Protection: {rt}")
        self.dash_findings.configure(text=f"Total Findings (session): {self.total_findings}")
        self.dash_last_scan.configure(text=f"Last Scan: {self.last_scan_time or '—'}")

    def _set_status(self, text):
        self.status_lbl.configure(text=f"Status: {text}")

    def _set_progress(self, val):
        try:
            self.prog["value"] = max(0, min(100, int(val)))
            self.update_idletasks()
        except Exception:
            pass

    def _open_folder(self, path):
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            pass

    def _about(self):
        messagebox.showinfo("About", "PyGuardian X\nEducational antivirus-style scanner with GUI\nReal-time protection, quarantine, scheduler, and more.")

    def _info(self, msg):
        append_log(msg)
        messagebox.showinfo("PyGuardian X", msg)

    def _warn(self, msg):
        append_log("WARN: " + msg)
        messagebox.showwarning("PyGuardian X", msg)

    def _hash_dialog(self):
        p = filedialog.askopenfilename()
        if not p:
            return
        try:
            h = sha256_file(p)
            self.hash_out.delete(0, "end")
            self.hash_out.insert(0, h)
        except Exception as e:
            self._warn(f"Hash failed: {e}")

    def _import_sigs(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                self._warn("Invalid signatures file")
                return
            storage.signatures.update(data)
            storage.save_signatures()
            self._info("Signatures imported")
        except Exception as e:
            self._warn(f"Import failed: {e}")

    def _export_sigs(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(storage.signatures, f, indent=2)
            self._info("Signatures exported")
        except Exception as e:
            self._warn(f"Export failed: {e}")

    def _add_sig(self):
        text = self.sig_add_entry.get().strip()
        if "=" not in text:
            self._warn("Use format name=sha256")
            return
        name, h = [x.strip() for x in text.split("=", 1)]
        if not re.fullmatch(r"[0-9a-fA-F]{64}", h):
            self._warn("Invalid SHA-256")
            return
        storage.signatures[name] = h.lower()
        storage.save_signatures()
        self._info("Signature added")
        self.sig_add_entry.delete(0, "end")

    def _gen_eicar(self):
        p = filedialog.asksaveasfilename(defaultextension=".com", initialfile="eicar.com", filetypes=[("All", "*.*")])
        if not p:
            return
        try:
            payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            with open(p, "wb") as f:
                f.write(payload)
            self._info("EICAR test file created")
        except Exception as e:
            self._warn(f"Create failed: {e}")

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    if not os.path.exists(SIG_PATH):
        storage.save_signatures()
    if not os.path.exists(CONFIG_PATH):
        storage.save_config()
    main()
