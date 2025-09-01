#!/usr/bin/env python3
import os, sys, time, json, threading, subprocess, shlex, xml.etree.ElementTree as ET, signal
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

# Optional Windows PATH helper for nmap.exe
POSSIBLE_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
]
for p in POSSIBLE_PATHS:
    if os.name == "nt" and os.path.exists(p):
        os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
        break

BRUTE_SCRIPTS = {
    "ssh-brute": {"ports": "22"},
    "ftp-brute": {"ports": "21"},
    "telnet-brute": {"ports": "23"},
    "http-brute": {"ports": "80,443"},
    "http-form-brute": {"ports": "80,443"},
    "vnc-brute": {"ports": "5900"},
    "ms-sql-brute": {"ports": "1433"},
}

SCRIPT_TYPES = {
    "": {"preset": "", "suboptions": []},
    "default": {"preset": "default", "suboptions": []},
    "vuln": {"preset": "vuln", "suboptions": []},
    "auth": {"preset": "auth", "suboptions": []},
    "brute": {"preset": "brute", "suboptions": sorted(BRUTE_SCRIPTS.keys())},
    "http": {"preset": "http-*", "suboptions": ["http-enum", "http-title", "http-headers", "http-auth", "http-robots.txt"]},
    "safe": {"preset": "safe", "suboptions": []},
    "intrusive": {"preset": "intrusive", "suboptions": []},
}

class NmapGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NScan GUI")
        self.geometry("1080x860")
        self.resizable(True, True)

        # Runtime state
        self._scan_thread = None
        self._proc = None
        self._stop_requested = False
        self._start_time = None
        self.last_scan = None  # parsed XML when XML mode selected

        self._build_widgets()
        self._update_status_loop()

    # --------------- UI ---------------
    def _build_widgets(self):
        frm_top = ttk.LabelFrame(self, text="Targets & Coverage")
        frm_top.pack(fill="x", padx=10, pady=6)

        ttk.Label(frm_top, text="Targets (CIDR/host/list):").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.targets_var = tk.StringVar()
        ttk.Entry(frm_top, textvariable=self.targets_var, width=60).grid(row=0, column=1, columnspan=4, sticky="we", padx=6, pady=4)

        # All toggle
        self.all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_top, text="All (Service+OS+Aggressive)", variable=self.all_var, command=self._on_all_toggle).grid(row=0, column=5, padx=6, pady=2, sticky="e")

        self.fast_var = tk.BooleanVar()
        self.full_var = tk.BooleanVar()
        self.service_var = tk.BooleanVar()
        self.os_var = tk.BooleanVar()
        self.aggr_var = tk.BooleanVar()
        self.disc_var = tk.BooleanVar()
        self.noping_var = tk.BooleanVar()
        self.onlyopen_var = tk.BooleanVar()
        self.verbose_var = tk.BooleanVar()
        self.unpriv_var = tk.BooleanVar()  

        ttk.Checkbutton(frm_top, text="Fast (-F)", variable=self.fast_var, command=self._on_mode_toggle).grid(row=1, column=0, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="Full TCP (-p-)", variable=self.full_var, command=self._on_mode_toggle).grid(row=1, column=1, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="Service (-sV)", variable=self.service_var, command=self._sync_all_from_children).grid(row=1, column=2, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="OS (-O)", variable=self.os_var, command=self._sync_all_from_children).grid(row=1, column=3, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="Aggressive (-A)", variable=self.aggr_var, command=self._sync_all_from_children).grid(row=1, column=4, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="No ping (-Pn)", variable=self.noping_var).grid(row=1, column=5, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="Only open (--open)", variable=self.onlyopen_var).grid(row=1, column=6, padx=6, pady=2, sticky="w")

        ttk.Label(frm_top, text="Common ports count (--top-ports):").grid(row=2, column=0, sticky="e", padx=6)
        self.topn_var = tk.StringVar()
        self.topn_entry = ttk.Entry(frm_top, textvariable=self.topn_var, width=10)
        self.topn_entry.grid(row=2, column=1, sticky="w", padx=2)

        ttk.Label(frm_top, text="Ports (e.g., 22,80,443 or 1-1024):").grid(row=2, column=2, sticky="e", padx=6)
        self.ports_var = tk.StringVar()
        self.ports_entry = ttk.Entry(frm_top, textvariable=self.ports_var, width=24)
        self.ports_entry.grid(row=2, column=3, sticky="w", padx=2)

        ttk.Label(frm_top, text="Timing -T0..5:").grid(row=2, column=4, sticky="e", padx=6)
        self.timing_var = tk.StringVar()
        ttk.Combobox(frm_top, textvariable=self.timing_var, values=["", "0", "1", "2", "3", "4", "5"], width=4).grid(row=2, column=5, sticky="w")

        ttk.Checkbutton(frm_top, text="Verbose (-v)", variable=self.verbose_var).grid(row=2, column=6, padx=6, pady=2, sticky="w")
        ttk.Checkbutton(frm_top, text="Unprivileged mode", variable=self.unpriv_var).grid(row=2, column=7, padx=6, pady=2, sticky="w")

        # Output format
        ttk.Label(frm_top, text="Output format:").grid(row=3, column=0, sticky="e", padx=6)
        self.outfmt_var = tk.StringVar(value="Normal (CLI)")
        ttk.Combobox(frm_top, textvariable=self.outfmt_var, values=["Normal (CLI)", "XML"], width=14, state="readonly").grid(row=3, column=1, sticky="w", padx=2)

        # NSE frame
        frm_nse = ttk.LabelFrame(self, text="NSE Scripts")
        frm_nse.pack(fill="x", padx=10, pady=6)

        ttk.Label(frm_nse, text="Script type:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.script_type_var = tk.StringVar(value="")
        self.script_type_combo = ttk.Combobox(frm_nse, textvariable=self.script_type_var, values=list(SCRIPT_TYPES.keys()), width=20, state="readonly")
        self.script_type_combo.grid(row=0, column=1, sticky="w", padx=6, pady=4)
        self.script_type_combo.bind("<<ComboboxSelected>>", self._on_script_type_change)

        ttk.Label(frm_nse, text="Type options:").grid(row=0, column=2, sticky="e", padx=6, pady=4)
        self.script_subopt_var = tk.StringVar(value="")
        self.script_subopt_combo = ttk.Combobox(frm_nse, textvariable=self.script_subopt_var, values=[], width=28, state="disabled")
        self.script_subopt_combo.grid(row=0, column=3, sticky="w", padx=6, pady=4)
        self.script_subopt_combo.bind("<<ComboboxSelected>>", self._on_script_suboption_selected)

        ttk.Label(frm_nse, text="Scripts (comma/wildcards):").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.scripts_var = tk.StringVar()
        ttk.Entry(frm_nse, textvariable=self.scripts_var, width=50).grid(row=1, column=1, sticky="we", padx=6, pady=4)

        ttk.Label(frm_nse, text="Script Args:").grid(row=1, column=2, sticky="e", padx=6, pady=4)
        self.script_args_var = tk.StringVar()
        ttk.Entry(frm_nse, textvariable=self.script_args_var, width=50).grid(row=1, column=3, sticky="we", padx=6, pady=4)

        ttk.Label(frm_nse, text="Brute force:").grid(row=2, column=0, sticky="w", padx=6, pady=4)
        self.brute_master_var = tk.StringVar(value="No")
        self.brute_master_combo = ttk.Combobox(frm_nse, textvariable=self.brute_master_var, values=["No", "Yes"], width=10, state="readonly")
        self.brute_master_combo.grid(row=2, column=1, sticky="w", padx=6, pady=4)
        self.brute_master_combo.bind("<<ComboboxSelected>>", self._on_brute_master_change)

        ttk.Label(frm_nse, text="Brute script:").grid(row=2, column=2, sticky="e", padx=6, pady=4)
        self.brute_var = tk.StringVar(value="")
        self.brute_combo = ttk.Combobox(frm_nse, textvariable=self.brute_var, values=sorted(BRUTE_SCRIPTS.keys()), width=28, state="disabled")
        self.brute_combo.grid(row=2, column=3, sticky="w", padx=6, pady=4)

        ttk.Label(frm_nse, text="Brute ports:").grid(row=3, column=2, sticky="e", padx=6)
        self.brute_ports_var = tk.StringVar()
        self.brute_ports_entry = ttk.Entry(frm_nse, textvariable=self.brute_ports_var, width=18, state="disabled")
        self.brute_ports_entry.grid(row=3, column=3, sticky="w", padx=2)

        # Advanced
        frm_extra = ttk.LabelFrame(self, text="Advanced")
        frm_extra.pack(fill="x", padx=10, pady=6)
        ttk.Label(frm_extra, text="Extra Nmap args:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.extra_var = tk.StringVar()
        ttk.Entry(frm_extra, textvariable=self.extra_var, width=80).grid(row=0, column=1, sticky="we", padx=6, pady=4)

        # Controls
        frm_ctrl = ttk.Frame(self)
        frm_ctrl.pack(fill="x", padx=10, pady=6)
        self.btn_run = ttk.Button(frm_ctrl, text="Run Scan", command=self._on_run)
        self.btn_stop = ttk.Button(frm_ctrl, text="Stop", command=self._on_stop)
        self.btn_clear = ttk.Button(frm_ctrl, text="Clear", command=self._on_clear)
        self.btn_save_json = ttk.Button(frm_ctrl, text="Save JSON", command=self._on_save_json)
        self.btn_save_csv = ttk.Button(frm_ctrl, text="Save CSV", command=self._on_save_csv)
        self.btn_exit = ttk.Button(frm_ctrl, text="Exit", command=self._on_exit)
        for b in (self.btn_run, self.btn_stop, self.btn_clear, self.btn_save_json, self.btn_save_csv, self.btn_exit):
            b.pack(side="left", padx=4)

        # Log/result pane
        frm_log = ttk.LabelFrame(self, text="Command & Results")
        frm_log.pack(fill="both", expand=True, padx=10, pady=6)
        self.log = scrolledtext.ScrolledText(frm_log, wrap="word", height=30)
        self.log.pack(fill="both", expand=True, padx=6, pady=6)
        self._append_log("Ready.\n")

        # Status bar
        status_frame = ttk.Frame(self)
        status_frame.pack(fill="x", side="bottom")
        ttk.Separator(status_frame, orient="horizontal").pack(fill="x", pady=(0,4))
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", length=160)
        self.progress.pack(side="left", padx=8, pady=6)
        self.status_var = tk.StringVar(value="Status: Idle")
        self.elapsed_var = tk.StringVar(value="Elapsed: 00:00")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side="left", padx=12)
        ttk.Label(status_frame, textvariable=self.elapsed_var).pack(side="right", padx=12)

    # --------------- Helpers ---------------
    def _append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_running_ui(self, running: bool):
        self.btn_run.configure(state=("disabled" if running else "normal"))
        self.btn_stop.configure(state=("normal" if running else "disabled"))
        self.btn_clear.configure(state=("disabled" if running else "normal"))
        self.btn_save_json.configure(state=("disabled" if running else "normal"))
        self.btn_save_csv.configure(state=("disabled" if running else "normal"))
        self.btn_exit.configure(state=("disabled" if running else "normal"))
        if running:
            self.progress.start(12)
            self._start_time = time.time()
            self.status_var.set("Status: Running")
        else:
            self.progress.stop()
            self.status_var.set("Status: Idle")

    def _on_exit(self):
        if self._proc:
            if not messagebox.askyesno("Exit", "A scan is running. Stop and exit?"):
                return
            self._on_stop()
            self.after(300, self.destroy)
        else:
            self.destroy()

    def _on_all_toggle(self):
        if self.all_var.get():
            self.service_var.set(True)
            self.os_var.set(True)
            self.aggr_var.set(True)
        else:
            self.service_var.set(False)
            self.os_var.set(False)
            self.aggr_var.set(False)

    def _sync_all_from_children(self):
        self.all_var.set(self.service_var.get() and self.os_var.get() and self.aggr_var.get())

    def _on_mode_toggle(self):
        if self.fast_var.get():
            self.full_var.set(False)
            self.ports_var.set("")
        if self.full_var.get():
            self.fast_var.set(False)
            self.topn_var.set("")
            self.ports_var.set("")

    def _on_script_type_change(self, event=None):
        stype = self.script_type_var.get()
        preset = SCRIPT_TYPES.get(stype, {}).get("preset", "")
        subopts = SCRIPT_TYPES.get(stype, {}).get("suboptions", [])
        if subopts:
            self.script_subopt_combo.configure(state="readonly", values=subopts)
            if self.script_subopt_var.get() not in subopts:
                self.script_subopt_var.set(subopts)
        else:
            self.script_subopt_combo.configure(state="disabled", values=[])
            self.script_subopt_var.set("")
        self._merge_script_preset(preset)
        if stype == "brute":
            self.brute_master_var.set("Yes")
            self._on_brute_master_change()

    def _on_script_suboption_selected(self, event=None):
        val = self.script_subopt_var.get().strip()
        if not val:
            return
        current = [s for s in self.scripts_var.get().split(",") if s.strip()]
        if val not in current:
            current.append(val)
            self.scripts_var.set(",".join(current))

    def _merge_script_preset(self, preset: str):
        if not preset:
            return
        items = [s for s in self.scripts_var.get().split(",") if s.strip()]
        if preset not in items:
            items.append(preset)
            self.scripts_var.set(",".join(items))

    def _on_brute_master_change(self, event=None):
        yes = self.brute_master_var.get() == "Yes"
        self.brute_combo.configure(state=("readonly" if yes else "disabled"))
        self.brute_ports_entry.configure(state=("normal" if yes else "disabled"))
        if yes and not self.brute_var.get():
            self.brute_var.set(sorted(BRUTE_SCRIPTS.keys()))
            default_ports = BRUTE_SCRIPTS[self.brute_var.get()]["ports"]
            self.brute_ports_var.set(default_ports)

    def _validate_topn(self, value: str):
        value = value.strip()
        if not value:
            return None
        try:
            n = int(value)
            if n < 1 or n > 65535:
                raise ValueError
            return n
        except Exception:
            messagebox.showerror("Common ports count", "Enter a number between 1 and 65535.")
            return None

    def _build_args_and_argv(self, targets: str):
        args = []
        if self.disc_var.get():
            args.append("-sn")
        if self.fast_var.get():
            args.append("-F")
        topn = self._validate_topn(self.topn_var.get())
        ports = self.ports_var.get().strip()
        if topn and not self.full_var.get() and not ports:
            if topn > 4096:
                self._append_log("[Notice] Large common ports count may be unstable on some builds; using full scan (-p-) instead.\n")
                args.append("-p-")
            else:
                args += ["--top-ports", str(topn)]
        if self.full_var.get():
            args.append("-p-")
        if ports:
            if "-F" in args:
                args.remove("-F")
            args += ["-p", ports]

        # Privilege-aware: if unprivileged, prefer -sT and avoid -O unless explicit
        if self.unpriv_var.get():
            if "-sV" not in args and not self.aggr_var.get():
                args.append("-sT")  # connect scan works unprivileged [10]
            # Don't auto-add -O in unprivileged mode
        # Detection flags
        if self.aggr_var.get():
            args.append("-A")  # will only enable OS/traceroute if privileged [8]
        else:
            if self.service_var.get() and "-sV" not in args:
                args.append("-sV")
            if self.os_var.get():
                args.append("-O")
        if self.noping_var.get():
            args.append("-Pn")
        if self.onlyopen_var.get():
            args.append("--open")
        if self.verbose_var.get():
            args.append("-v")
        timing = self.timing_var.get().strip()
        if timing:
            args.append(f"-T{timing}")

        # NSE
        scripts = self.scripts_var.get().strip()
        if self.brute_master_var.get() == "Yes":
            brute = self.brute_var.get().strip()
            if brute:
                scripts = f"{scripts},{brute}" if scripts else brute
                if not ports and "--top-ports" not in args and "-p-" not in args and "-F" not in args:
                    bports = self.brute_ports_var.get().strip() or BRUTE_SCRIPTS[brute]["ports"]
                    if bports:
                        args += ["-p", bports]
        if scripts:
            args += ["--script", scripts]
        script_args = self.script_args_var.get().strip()
        if script_args:
            args += ["--script-args", script_args]
        extra = self.extra_var.get().strip()
        if extra:
            parts = shlex.split(extra, posix=(os.name != "nt"))
            args += parts

        # Cooperative time limits for responsiveness
        if not any(a.startswith("--host-timeout") for a in args):
            args += ["--host-timeout", "60s"]
        if ("--script" in args) and not any(a.startswith("--script-timeout") for a in args):
            args += ["--script-timeout", "120s"]

        argv = ["nmap"] + args + shlex.split(targets, posix=(os.name != "nt"))
        # Choose stdout format (no files)
        if self.outfmt_var.get().startswith("Normal"):
            argv += ["-oN", "-"]  # stream normal output to stdout [13]
        else:
            argv += ["-oX", "-"]  # stream XML to stdout [14]
        return args, argv

    # --------------- Process control ---------------
    def _spawn_nmap(self, argv):
        if os.name == "nt":
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            return subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr -> stdout [1]
                text=True,
                creationflags=CREATE_NEW_PROCESS_GROUP,
                bufsize=1  # line-buffered [7]
            )
        else:
            return subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr -> stdout [1]
                text=True,
                start_new_session=True,    # new process group for signals
                bufsize=1                  # line-buffered [7]
            )

    def _graceful_stop(self):
        if not self._proc:
            return
        try:
            if os.name == "nt":
                self._proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(self._proc.pid, signal.SIGTERM)
        except Exception:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _force_kill(self):
        if not self._proc:
            return
        try:
            if os.name == "nt":
                self._proc.kill()
            else:
                os.killpg(self._proc.pid, signal.SIGKILL)
        except Exception:
            pass

    # --------------- Scan thread ---------------
    def _run_scan_thread(self, argv):
        self._stop_requested = False
        self._set_running_ui(True)
        shown = " ".join(shlex.quote(a) if os.name != "nt" else a for a in argv)
        self._append_log("\nRunning: " + shown + "\n")

        try:
            self._proc = self._spawn_nmap(argv)
            xml_chunks = []
            # Robust line streaming: iterate until EOF, then check poll [1][7]
            while True:
                line = self._proc.stdout.readline()
                if line:
                    self._append_log(line)
                    if self.outfmt_var.get().startswith("XML"):
                        xml_chunks.append(line)
                else:
                    # No line; check if process ended
                    rc = self._proc.poll()
                    if rc is not None:
                        break
                    time.sleep(0.05)
                if self._stop_requested:
                    self._append_log("\nStopping scan...\n")
                    self._graceful_stop()
                    # After signaling, loop continues until poll() != None
            # Ensure exit; if not, force-kill
            try:
                self._proc.wait(timeout=2)
            except Exception:
                self._append_log("\n[Force kill] Scan did not stop gracefully; killing process...\n")
                self._force_kill()

            ret = self._proc.poll()

            # Segfault retry if using --top-ports (exit 139 on Unix) [1]
            if ret == 139 and any(a == "--top-ports" for a in argv):
                self._append_log("\n[Warning] Nmap crashed (segmentation fault). Retrying with full scan (-p-)...\n")
                cleaned = []
                skip_next = False
                for a in argv:
                    if skip_next:
                        skip_next = False
                        continue
                    if a == "--top-ports":
                        skip_next = True
                        continue
                    cleaned.append(a)
                if "-p-" not in cleaned:
                    cleaned.insert(1, "-p-")
                self._proc = self._spawn_nmap(cleaned)
                xml_chunks = [] if self.outfmt_var.get().startswith("XML") else xml_chunks
                while True:
                    line = self._proc.stdout.readline()
                    if line:
                        self._append_log(line)
                        if self.outfmt_var.get().startswith("XML"):
                            xml_chunks.append(line)
                    else:
                        rc = self._proc.poll()
                        if rc is not None:
                            break
                        time.sleep(0.05)
                try:
                    self._proc.wait(timeout=2)
                except Exception:
                    self._force_kill()

            # Parse XML if chosen
            if self.outfmt_var.get().startswith("XML"):
                xml_text = "".join(xml_chunks).strip()
                self.last_scan = None
                if "<nmaprun" in xml_text:
                    try:
                        self.last_scan = self._parse_nmap_xml(xml_text)
                        self._append_log("\n[Parsed results captured]\n")
                    except Exception as ex:
                        self._append_log(f"\n[XML parse error] {ex}\n")
                else:
                    self._append_log("\n[No XML results captured]\n")

        except FileNotFoundError:
            self._append_log("\nError: nmap was not found. Install Nmap and add it to PATH.\n")
        except Exception as e:
            self._append_log(f"\nError: {e}\n")
        finally:
            self._proc = None
            self._set_running_ui(False)
            self._stop_requested = False

    def _parse_nmap_xml(self, xml_text: str):
        root = ET.fromstring(xml_text)
        args_attr = root.attrib.get("args", "")
        out = {"command": args_attr, "hosts": []}
        for h in root.findall("host"):
            status = h.find("status")
            addr = h.find("address")
            hostnames = h.find("hostnames")
            hostname = ""
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.attrib.get("name", "")
            ip = addr.attrib.get("addr", "") if addr is not None else ""
            state = status.attrib.get("state", "") if status is not None else ""
            host_entry = {"host": ip or "", "hostname": hostname, "state": state, "protocols": {}}
            for ports in h.findall("ports"):
                for p in ports.findall("port"):
                    proto = p.attrib.get("protocol", "tcp")
                    portid = int(p.attrib.get("portid", "0"))
                    state_el = p.find("state")
                    service_el = p.find("service")
                    pdata = {
                        "port": portid,
                        "state": state_el.attrib.get("state", "") if state_el is not None else "",
                        "name": service_el.attrib.get("name", "") if service_el is not None else "",
                        "product": service_el.attrib.get("product", "") if service_el is not None else "",
                        "version": service_el.attrib.get("version", "") if service_el is not None else "",
                        "extrainfo": service_el.attrib.get("extrainfo", "") if service_el is not None else "",
                        "reason": state_el.attrib.get("reason", "") if state_el is not None else "",
                        "cpe": service_el.findtext("cpe", default="") if service_el is not None else "",
                    }
                    host_entry.setdefault("protocols", {}).setdefault(proto, []).append(pdata)
            out["hosts"].append(host_entry)
        return out

    # --------------- Events ---------------
    def _on_run(self):
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Scan running", "A scan is already running.")
            return
        targets = self.targets_var.get().strip()
        if not targets:
            messagebox.showerror("Error", "Please enter targets.")
            return
        _, argv = self._build_args_and_argv(targets)
        self._scan_thread = threading.Thread(target=self._run_scan_thread, args=(argv,), daemon=True)
        self._scan_thread.start()

    def _on_stop(self):
        if not self._proc:
            messagebox.showinfo("Stop", "No scan is currently running.")
            return
        self.status_var.set("Status: Stopping...")
        self._stop_requested = True
        self._graceful_stop()
        self.after(1500, self._maybe_force_kill)

    def _maybe_force_kill(self):
        if self._proc and (self._proc.poll() is None):
            self._append_log("\n[Force kill] Scan did not stop gracefully; killing process...\n")
            self._force_kill()

    def _on_clear(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.insert("end", "Ready.\n")
        self.log.configure(state="disabled")
        self.last_scan = None

        self.targets_var.set("")
        self.fast_var.set(False)
        self.full_var.set(False)
        self.service_var.set(False)
        self.os_var.set(False)
        self.aggr_var.set(False)
        self.disc_var.set(False)
        self.noping_var.set(False)
        self.onlyopen_var.set(False)
        self.verbose_var.set(False)
        self.unpriv_var.set(False)
        self.all_var.set(False)
        self.topn_var.set("")
        self.ports_var.set("")
        self.timing_var.set("")
        self.scripts_var.set("")
        self.script_args_var.set("")
        self.script_type_var.set("")
        self.script_subopt_var.set("")
        self.brute_master_var.set("No")
        self.brute_var.set("")
        self.brute_ports_var.set("")
        self.brute_combo.configure(state="disabled")
        self.brute_ports_entry.configure(state="disabled")
        self.script_subopt_combo.configure(state="disabled", values=[])

    def _on_save_json(self):
        if not self.last_scan:
            messagebox.showinfo("Save JSON", "No results to save. Use XML mode to capture structured data.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, "w") as f:
                json.dump(self.last_scan, f, indent=2)
            self._append_log(f"Saved JSON to {path}\n")

    def _on_save_csv(self):
        if not self.last_scan:
            messagebox.showinfo("Save CSV", "No parsed results to export. Use XML mode for structured export.")
            return
        import csv
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["host","hostname","state","protocol","port","service","product","version","extrainfo","reason","cpe"])
            for h in self.last_scan.get("hosts", []):
                for proto, plist in h.get("protocols", {}).items():
                    for p in plist:
                        writer.writerow([
                            h.get("host",""), h.get("hostname",""), h.get("state",""),
                            proto, p.get("port",""), p.get("name",""), p.get("product",""),
                            p.get("version",""), p.get("extrainfo",""), p.get("reason",""), p.get("cpe","")
                        ])
        self._append_log(f"Saved CSV to {path}\n")

    # --------------- Status loop ---------------
    def _update_status_loop(self):
        if self._start_time and (self._proc or (self._scan_thread and self._scan_thread.is_alive())):
            elapsed = int(time.time() - self._start_time)
            mm, ss = divmod(elapsed, 60)
            self.elapsed_var.set(f"Elapsed: {mm:02d}:{ss:02d}")
        else:
            self.elapsed_var.set("Elapsed: 00:00")
        self.after(500, self._update_status_loop)

if __name__ == "__main__":
    app = NmapGUI()
    def on_close():
        if app._proc:
            if not messagebox.askyesno("Exit", "A scan is running. Stop and exit?"):
                return
            app._on_stop()
            app.after(300, app.destroy)
        else:
            app.destroy()
    app.protocol("WM_DELETE_WINDOW", on_close)
    app.mainloop()
