import os, sys, json, hashlib, shutil, threading, queue, datetime, re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except:
    WATCHDOG_AVAILABLE = False

APP_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), ".pyguardian")
os.makedirs(APP_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
SIG_PATH = os.path.join(APP_DIR, "signatures.json")
QUAR_META_PATH = os.path.join(APP_DIR, "quarantine.json")
LOG_PATH = os.path.join(APP_DIR, "events.log")
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "heuristics_enabled": True,
    "max_scan_bytes": 1024*1024,
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
]

# Storage management
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
        self.sig_hash_to_name = {h:n for n,h in self.signatures.items()}
        self.quarantine_meta = self._load_json(QUAR_META_PATH, {})
    def save_config(self): self._save_json(CONFIG_PATH, self.config)
    def save_signatures(self): 
        self._save_json(SIG_PATH, self.signatures)
        self.sig_hash_to_name = {h:n for n,h in self.signatures.items()}
    def save_quarantine(self): self._save_json(QUAR_META_PATH, self.quarantine_meta)
    def _load_json(self,path,default):
        try:
            if os.path.exists(path):
                return json.load(open(path,"r",encoding="utf-8"))
        except: pass
        return json.loads(json.dumps(default))
    def _save_json(self,path,data):
        tmp=path+".tmp"
        with open(tmp,"w",encoding="utf-8") as f: json.dump(data,f,indent=2)
        os.replace(tmp,path)

storage = Storage()

def append_log(msg):
    ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line=f"[{ts}] {msg}"
    try: open(LOG_PATH,"a",encoding="utf-8").write(line+"\n")
    except: pass
    return line

def sha256_file(path,block_size=1024*1024):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        while True:
            chunk=f.read(block_size)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

def is_probably_text(data: bytes) -> bool:
    try:
        s=data.decode("utf-8")
        printable=sum(1 for ch in s if ch.isprintable() or ch.isspace())
        return printable/max(1,len(s))>0.85
    except: return False

def scan_buffer_for_heuristics(buf: bytes):
    findings=[]
    for name,rx in HEURISTIC_PATTERNS:
        if rx.search(buf):
            findings.append(f"Heuristic:{name}")
    return findings

def is_whitelisted(path):
    for item in storage.config.get("whitelist", []):
        try: 
            if os.path.abspath(path).startswith(os.path.abspath(item)):
                return True
        except: pass
    return False

def is_excluded_dir(base):
    for d in storage.config.get("exclude_dirs", []):
        if os.path.abspath(base).startswith(os.path.abspath(d)):
            return True
    return False

def scan_file(path):
    results=[]
    try:
        if is_whitelisted(path): return []
        digest=sha256_file(path)
        if digest in storage.sig_hash_to_name:
            results.append(("Signature:"+storage.sig_hash_to_name[digest], "high"))
        if storage.config.get("heuristics_enabled", True):
            tsniff=int(storage.config.get("text_sniff_bytes",4096))
            cap=int(storage.config.get("max_scan_bytes",1024*1024))
            with open(path,"rb") as f:
                sniff=f.read(tsniff)
                if is_probably_text(sniff):
                    buf=sniff+f.read(max(0,cap-len(sniff)))
                    for reason in scan_buffer_for_heuristics(buf):
                        results.append((reason,"medium"))
    except: return results
    return results

def iter_files(root):
    for base,dirs,files in os.walk(root):
        if is_excluded_dir(base): dirs[:] = []; continue
        dirs[:] = [d for d in dirs if not is_excluded_dir(os.path.join(base,d))]
        for fname in files: yield os.path.join(base,fname)

def quarantine_move(path, reason):
    try:
        digest=None
        try: digest=sha256_file(path)
        except: pass
        ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest=os.path.join(QUARANTINE_DIR,f"{ts}__{os.path.basename(path)}")
        shutil.move(path,dest)
        storage.quarantine_meta[dest]={"original_path":path,"reason":reason,"timestamp":ts,"sha256":digest}
        storage.save_quarantine()
        append_log(f"Quarantined: {path} -> {dest}")
        return dest
    except: return None

def quarantine_restore(quar_path):
    meta=storage.quarantine_meta.get(quar_path)
    if not meta: return False,"No metadata"
    orig=meta.get("original_path","")
    try:
        os.makedirs(os.path.dirname(orig) or ".", exist_ok=True)
        shutil.move(quar_path, orig)
        del storage.quarantine_meta[quar_path]
        storage.save_quarantine()
        append_log(f"Restored: {quar_path} -> {orig}")
        return True, orig
    except Exception as e: return False,str(e)

def quarantine_delete(quar_path):
    try: os.remove(quar_path)
    except: pass
    if quar_path in storage.quarantine_meta:
        del storage.quarantine_meta[quar_path]
        storage.save_quarantine()
    append_log(f"Deleted from quarantine: {quar_path}")
    return True

class TaskThread(threading.Thread):
    def __init__(self,target,args=()): super().__init__(daemon=True); self.target=target; self.args=args; self.exc=None
    def run(self):
        try: self.target(*self.args)
        except Exception as e: self.exc=e

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyGuardian X")
        self.geometry("1080x720")
        self.minsize(960,640)
        self.configure(bg="#1e1e2f")
        self.style=ttk.Style()
        self._apply_theme()
        self.event_queue=queue.Queue()
        self.scan_queue=queue.Queue()
        self.current_scans=0
        self.total_findings=0
        self.last_scan_time=None
        self._build_ui()
        self.after(100,self._drain_event_queue)
        self.after(150,self._drain_scan_queue)

    def _apply_theme(self):
        self.style.theme_use("default")
        self.style.configure("TLabel", background="#1e1e2f", foreground="#e0e0e0", font=("Segoe UI",12))
        self.style.configure("TButton", font=("Segoe UI",11), padding=8)
        self.style.map("TButton", background=[("active","#4b6cf7")], foreground=[("active","#ffffff")])
        self.style.configure("Treeview", font=("Segoe UI",11), rowheight=28, background="#2e2e3f", fieldbackground="#2e2e3f", foreground="#e0e0e0")
        self.style.configure("Treeview.Heading", font=("Segoe UI",12,"bold"), background="#3b3b5c", foreground="#ffffff")
        self.style.configure("TNotebook.Tab", font=("Segoe UI",11,"bold"), padding=(12,8))

    def _build_ui(self):
        top_frame=ttk.Frame(self,padding=10); top_frame.pack(fill="x")
        self.status_lbl=ttk.Label(top_frame,text="Status: Idle", font=("Segoe UI",14))
        self.status_lbl.pack(side="left")
        self.prog=ttk.Progressbar(top_frame, mode="determinate", length=240)
        self.prog.pack(side="left", padx=10); self.prog["value"]=0
        self.nb=ttk.Notebook(self); self.nb.pack(fill="both",expand=True, padx=10, pady=10)

        self.tab_manual=ttk.Frame(self.nb); self.nb.add(self.tab_manual,text="Manual Scan")
        self.tab_realtime=ttk.Frame(self.nb); self.nb.add(self.tab_realtime,text="Real-Time")
        self.tab_quar=ttk.Frame(self.nb); self.nb.add(self.tab_quar,text="Quarantine")
        self.tab_logs=ttk.Frame(self.nb); self.nb.add(self.tab_logs,text="Logs")
        self.tab_tools=ttk.Frame(self.nb); self.nb.add(self.tab_tools,text="Tools")

        # Manual Scan
        btn_file=ttk.Button(self.tab_manual,text="Scan File",command=self._scan_file_dialog)
        btn_file.pack(pady=8)
        btn_folder=ttk.Button(self.tab_manual,text="Scan Folder",command=self._scan_folder_dialog)
        btn_folder.pack(pady=8)
        self.manual_log=ScrolledText(self.tab_manual, height=20, bg="#2e2e3f", fg="#e0e0e0")
        self.manual_log.pack(fill="both",expand=True, padx=10, pady=10)

        # Real-time
        self.rt_paths=list(storage.config.get("realtime_paths",[]))
        self.rt_tree=ttk.Treeview(self.tab_realtime,columns=("path","status"),show="headings")
        self.rt_tree.heading("path",text="Path"); self.rt_tree.heading("status",text="Status")
        self.rt_tree.pack(fill="both",expand=True, padx=10,pady=10)
        self._update_rt_tree()
        btn_add=ttk.Button(self.tab_realtime,text="Add Path",command=self._rt_add_path)
        btn_add.pack(side="left", padx=5, pady=5)
        btn_start=ttk.Button(self.tab_realtime,text="Start Monitoring",command=self._rt_start)
        btn_start.pack(side="left", padx=5,pady=5)
        btn_stop=ttk.Button(self.tab_realtime,text="Stop Monitoring",command=self._rt_stop)
        btn_stop.pack(side="left", padx=5,pady=5)

        # Quarantine
        self.quar_tree=ttk.Treeview(self.tab_quar,columns=("file","reason"),show="headings")
        self.quar_tree.heading("file",text="File"); self.quar_tree.heading("reason",text="Reason")
        self.quar_tree.pack(fill="both",expand=True,padx=10,pady=10)
        self._update_quar_tree()
        btn_restore=ttk.Button(self.tab_quar,text="Restore Selected",command=self._quar_restore)
        btn_restore.pack(side="left", padx=5,pady=5)
        btn_del=ttk.Button(self.tab_quar,text="Delete Selected",command=self._quar_delete)
        btn_del.pack(side="left", padx=5,pady=5)

        # Logs
        self.logs_text=ScrolledText(self.tab_logs,bg="#2e2e3f",fg="#e0e0e0")
        self.logs_text.pack(fill="both",expand=True,padx=10,pady=10)
        self._load_logs()

        # Tools
        btn_gen_eicar=ttk.Button(self.tab_tools,text="Generate EICAR Test File",command=self._gen_eicar)
        btn_gen_eicar.pack(pady=10)

    # Event Queue Drain
    def _drain_event_queue(self):
        while not self.event_queue.empty():
            msg=self.event_queue.get()
            self.status_lbl.config(text=f"Status: {msg}")
        self.after(100,self._drain_event_queue)

    def _drain_scan_queue(self):
        updated=False
        while not self.scan_queue.empty():
            path,findings=self.scan_queue.get()
            updated=True
            if findings:
                self.manual_log.insert("end",f"{path}: {findings}\n")
                self.manual_log.see("end")
                self.total_findings+=len(findings)
                quarantine_move(path,str(findings))
        if updated: self.prog["value"]=0
        self.after(150,self._drain_scan_queue)

    # Manual Scan
    def _scan_file_dialog(self):
        f=filedialog.askopenfilename()
        if f: self._scan_paths([f])

    def _scan_folder_dialog(self):
        f=filedialog.askdirectory()
        if f: self._scan_paths(list(iter_files(f)))

    def _scan_paths(self,paths):
        def task():
            self.event_queue.put("Scanning...")
            total=len(paths)
            for i,path in enumerate(paths):
                findings=scan_file(path)
                self.scan_queue.put((path,findings))
                self.prog["value"]=(i+1)/total*100
            self.event_queue.put("Idle")
        TaskThread(task).start()

    # Real-time
    def _update_rt_tree(self):
        for r in self.rt_tree.get_children(): self.rt_tree.delete(r)
        for p in self.rt_paths: self.rt_tree.insert("", "end", values=(p,"Stopped"))

    def _rt_add_path(self):
        f=filedialog.askdirectory()
        if f: 
            self.rt_paths.append(f)
            storage.config["realtime_paths"]=self.rt_paths
            storage.save_config()
            self._update_rt_tree()

    def _rt_start(self):
        if not WATCHDOG_AVAILABLE:
            messagebox.showwarning("Watchdog Missing","Install 'watchdog' for real-time scanning.")
            return
        self.rt_observers=[]
        class EventHandler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    findings=scan_file(event.src_path)
                    if findings: quarantine_move(event.src_path,str(findings))
        for p in self.rt_paths:
            observer=Observer()
            observer.schedule(EventHandler(), p, recursive=True)
            observer.start()
            self.rt_observers.append(observer)
        for i,item in enumerate(self.rt_tree.get_children()):
            self.rt_tree.set(item,"status","Running")

    def _rt_stop(self):
        if hasattr(self,"rt_observers"):
            for o in getattr(self,"rt_observers",[]): o.stop(); o.join()
            for i,item in enumerate(self.rt_tree.get_children()): self.rt_tree.set(item,"status","Stopped")

    # Quarantine
    def _update_quar_tree(self):
        for r in self.quar_tree.get_children(): self.quar_tree.delete(r)
        for f,m in storage.quarantine_meta.items(): self.quar_tree.insert("", "end", values=(os.path.basename(f),m.get("reason","")))

    def _quar_restore(self):
        sel=self.quar_tree.selection()
        for s in sel:
            fname=self.quar_tree.item(s,"values")[0]
            path=[k for k,v in storage.quarantine_meta.items() if os.path.basename(k)==fname]
            if path:
                ok,msg=quarantine_restore(path[0])
                if ok: append_log(f"Restored: {fname}")
        self._update_quar_tree()

    def _quar_delete(self):
        sel=self.quar_tree.selection()
        for s in sel:
            fname=self.quar_tree.item(s,"values")[0]
            path=[k for k,v in storage.quarantine_meta.items() if os.path.basename(k)==fname]
            if path: quarantine_delete(path[0])
        self._update_quar_tree()

    # Logs
    def _load_logs(self):
        try: self.logs_text.insert("end",open(LOG_PATH,"r",encoding="utf-8").read())
        except: pass

    # Tools
    def _gen_eicar(self):
        f=filedialog.asksaveasfilename(defaultextension=".com")
        if f:
            with open(f,"w") as out:
                out.write('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
            messagebox.showinfo("Done","EICAR test file generated.")

if __name__=="__main__":
    app=App()
    app.mainloop()
