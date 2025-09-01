**Overview**

NScan is a lightweight, cross‑platform GUI for Nmap that streams live scan output and makes powerful scans one‑click simple, supporting Normal and XML output modes with guided presets for common tasks. It provides quick toggles for fast/full/common‑ports scans, service/OS detection, aggressive profiling, and NSE workflows (default, vuln, auth, brute, http), all without external Python packages beyond a system Nmap install.

**Key features**

*   **Live output:** stream Nmap’s Normal CLI or XML directly in the app via `-oN -` or `-oX -`, without writing to disk by default.
*   **One‑click modes:** Fast (`-F`), Full TCP (`-p-`), Common ports count (`--top-ports N`), Only open (`--open`), No ping (`-Pn`), Verbose (`-v`), and timing (`-T0..5`).
*   **Detection presets:** toggle Service (`-sV`), OS (`-O`), and Aggressive (`-A`), or enable all at once using the “All” switch.
*   **NSE workflows:** choose a script type (default/vuln/auth/brute/http-*) and add contextual sub‑options like `http-enum`; brute helper suggests scripts and default ports.
*   **Reliable Stop:** launches Nmap in its own process group and sends graceful then force termination signals for cross‑platform reliability.
*   **Stability guardrails:** validates `--top-ports` input and auto‑retries with `-p-` if a crash is detected in older Nmap builds.
*   **Privilege aware:** optional “Unprivileged mode” prefers `-sT` and avoids OS detection unless explicitly requested.

**Requirements**

*   Python 3 with Tkinter (standard library; on Linux, install via OS package like `python3‑tk`).
*   Nmap installed and available on PATH; verify with `nmap --version` before running.

**How to run (Windows)**

1.  **Install Nmap:** run the official installer, accept the Npcap prompt, and add Nmap to PATH if offered; verify with `nmap --version` in a new terminal.
2.  **Python with Tkinter:** Python.org installers include Tkinter by default.
3.  **Launch:** open PowerShell in the project folder and run `py nscan.py` (or `python nscan.py`).

**How to run (Linux)**

1.  **Install Nmap:** Debian/Ubuntu `sudo apt install nmap`, Fedora/RHEL `sudo dnf install nmap`, Arch `sudo pacman -S nmap`; verify with `nmap --version`.
2.  **Install Tkinter:** Debian/Ubuntu `sudo apt-get install python3-tk`, Fedora `sudo dnf install python3-tkinter`, Arch `sudo pacman -S tk`.
3.  **Launch:** in the project folder run `python3 nscan.py`; for raw scans or OS detection, use `sudo` or enable “Unprivileged mode.”

**How to run (macOS)**

1.  **Install Nmap:** with Homebrew `brew install nmap` or use the official installer; verify with `nmap --version`.
2.  **Tkinter:** Python.org builds include Tkinter; if using Homebrew Python, ensure Tcl/Tk is available if import errors occur.
3.  **Launch:** in Terminal, `cd` to the project folder and run `python3 nscan.py`; use Normal (CLI) for live lines and XML for structured exports.

**Tips**

*   **Discovery blocked:** enable No ping (`-Pn`) and Only open (`--open`) to proceed and reduce noise.
*   **Progress feedback:** use Verbose (`-v`) for more frequent output during long scans.
*   **Large port sets:** prefer Full TCP (`-p-`) or moderate `--top-ports` values; upgrading Nmap resolves known crashes in older builds.

**Notes**

*   Zenmap is the official Nmap GUI; NScan is an independent front end focused on live streaming, presets, and safe defaults.
*   Use responsibly within authorized scope; aggressive or brute categories can trigger defenses on monitored networks.
