Python 3.8+ with Tkinter support: Tkinter ships with many Python builds; on Linux install via python3-tk package since it’s not provided by pip.

Nmap runtime: install Nmap and ensure nmap is on PATH; on Windows, the self-installer also handles Npcap prompts and VC++ runtime as needed.

No pip packages are strictly required for this GUI, since it uses subprocess, tkinter, threading, shlex, and xml.etree from the standard library only.

Platform notes:

Windows:

Install Nmap using the official self‑installer; ensure “Add to PATH” is set or add C:\Program Files (x86)\Nmap or C:\Program Files\Nmap manually; Npcap will be prompted by the installer.

Python includes Tkinter in most official distributions; no pip install is needed for Tkinter.
Linux:

Install Nmap via the distro (apt install nmap or dnf install nmap) and install Tkinter via python3-tk (e.g., apt install python3-tk).

Ensure nmap is available on PATH; verify with nmap --version.

macOS:

Install Nmap via Homebrew (brew install nmap) or official installer; verify on PATH with nmap --version.

Tkinter is included with Python.org builds; for Homebrew Python, ensure Tcl/Tk is available or install via brew if needed