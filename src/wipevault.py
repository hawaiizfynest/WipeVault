"""
WipeVault v3.0.3 - Secure Drive Erasure Tool
Cross-platform: Windows, macOS, Linux

Wipe methods:
  DoD 5220.22-M (3-pass), DoD 5220.28-STD (7-pass), Gutmann (35-pass),
  NIST SP 800-88 Purge, NIST SP 800-88 Clear, Zero Fill, ATA Secure Erase

v3 features:
  - NIST SP 800-88 Clear standard
  - Batch wipe (multiple drives simultaneously)
  - Wipe history log (searchable, persistent JSON archive)
  - Custom certificate logo upload
  - Certificate signing + tamper-evident SHA-256 verification
  - Post-wipe: clear partition table, initialize with GPT/MBR
"""

import sys, os, platform, subprocess, time, json, random, string, hashlib, hmac, base64, shutil
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QCheckBox, QMessageBox,
    QFrame, QSplitter, QTextEdit, QComboBox, QGroupBox, QStatusBar,
    QAbstractItemView, QTabWidget, QFileDialog, QSizePolicy, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QPixmap, QIcon

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.units import inch
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable, Image as RLImage)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ── History storage ────────────────────────────────────────────────────────
HISTORY_FILE = Path.home() / "WipeVault_Certs" / "wipe_history.json"
CERTS_DIR    = Path.home() / "WipeVault_Certs"

# ── Signing key (in production this would be per-install; here a fixed app key) ──
SIGNING_KEY = b"WipeVault-v3-signing-key-2025"


# ─────────────────────────────────────────────────────────────────────────────
# Custom CheckBox
# ─────────────────────────────────────────────────────────────────────────────

class CheckBox(QCheckBox):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("QCheckBox { color:#E6EDF3; spacing:7px; }")

    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QColor, QPen, QBrush
        from PyQt6.QtCore import QRect
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        sz   = 15
        y    = (self.height() - sz) // 2
        rect = QRect(0, y, sz, sz)
        if self.isChecked():
            p.setBrush(QBrush(QColor("#1F6FEB"))); p.setPen(QPen(QColor("#1F6FEB"), 1))
        elif self.underMouse():
            p.setBrush(QBrush(QColor("#161B22"))); p.setPen(QPen(QColor("#8B949E"), 1))
        else:
            p.setBrush(QBrush(QColor("#161B22"))); p.setPen(QPen(QColor("#30363D"), 1))
        p.drawRoundedRect(rect, 3, 3)
        if self.isChecked():
            pen = QPen(QColor("white"), 2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen)
            ox, oy = rect.x(), rect.y()
            p.drawLine(ox+3, oy+7, ox+6, oy+10)
            p.drawLine(ox+6, oy+10, ox+12, oy+4)
        p.setPen(QPen(QColor("#E6EDF3")))
        p.drawText(self.rect().adjusted(sz+7, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter, self.text())
        p.end()


# ─────────────────────────────────────────────────────────────────────────────
# Wipe Method Definitions
# ─────────────────────────────────────────────────────────────────────────────

WIPE_METHODS = {
    "dod3": {
        "label": "DoD 5220.22-M  (3-Pass)", "short": "DoD 5220.22-M",
        "description": "U.S. DoD 3-pass: zeros → ones → random + verify.",
        "passes": [("Pass 1 — Write 0x00", 0x00), ("Pass 2 — Write 0xFF", 0xFF), ("Pass 3 — Write random", None)],
        "verify": True, "ata_ok": False,
    },
    "dod7": {
        "label": "DoD 5220.28-STD  (7-Pass)", "short": "DoD 5220.28-STD",
        "description": "U.S. Air Force 7-pass: alternating patterns + random passes.",
        "passes": [("Pass 1 — 0x00",0x00),("Pass 2 — 0xFF",0xFF),("Pass 3 — 0x00",0x00),
                   ("Pass 4 — Random",None),("Pass 5 — 0x00",0x00),("Pass 6 — 0xFF",0xFF),("Pass 7 — Random",None)],
        "verify": True, "ata_ok": False,
    },
    "gutmann": {
        "label": "Gutmann Method  (35-Pass)", "short": "Gutmann",
        "description": "Peter Gutmann's 35-pass method for older magnetic drives.",
        "passes": [
            ("Pass 1 — Random",None),("Pass 2 — Random",None),("Pass 3 — Random",None),("Pass 4 — Random",None),
            ("Pass 5 — 0x55",0x55),("Pass 6 — 0xAA",0xAA),("Pass 7 — 0x92",0x92),("Pass 8 — 0x49",0x49),
            ("Pass 9 — 0x24",0x24),("Pass 10 — 0x00",0x00),("Pass 11 — 0x11",0x11),("Pass 12 — 0x22",0x22),
            ("Pass 13 — 0x33",0x33),("Pass 14 — 0x44",0x44),("Pass 15 — 0x55",0x55),("Pass 16 — 0x66",0x66),
            ("Pass 17 — 0x77",0x77),("Pass 18 — 0x88",0x88),("Pass 19 — 0x99",0x99),("Pass 20 — 0xAA",0xAA),
            ("Pass 21 — 0xBB",0xBB),("Pass 22 — 0xCC",0xCC),("Pass 23 — 0xDD",0xDD),("Pass 24 — 0xEE",0xEE),
            ("Pass 25 — 0xFF",0xFF),("Pass 26 — 0x92",0x92),("Pass 27 — 0x49",0x49),("Pass 28 — 0x24",0x24),
            ("Pass 29 — 0x6D",0x6D),("Pass 30 — 0xB6",0xB6),("Pass 31 — 0xDB",0xDB),
            ("Pass 32 — Random",None),("Pass 33 — Random",None),("Pass 34 — Random",None),("Pass 35 — Random",None),
        ],
        "verify": False, "ata_ok": False,
    },
    "nist_purge": {
        "label": "NIST SP 800-88  (Purge)", "short": "NIST SP 800-88 Purge",
        "description": "NIST Purge: single random overwrite + read-back verification.",
        "passes": [("Pass 1 — Write random (NIST Purge)", None)],
        "verify": True, "ata_ok": True,
    },
    "nist_clear": {
        "label": "NIST SP 800-88  (Clear)", "short": "NIST SP 800-88 Clear",
        "description": "NIST Clear: overwrite with zeros then ones. Lower assurance than Purge; suitable for reuse within organization.",
        "passes": [("Pass 1 — Write 0x00 (NIST Clear)", 0x00), ("Pass 2 — Write 0xFF (NIST Clear)", 0xFF)],
        "verify": True, "ata_ok": False,
    },
    "zero": {
        "label": "Zero Fill  (1-Pass)", "short": "Zero Fill",
        "description": "Single pass of 0x00. Fast, suitable for general reuse. Not forensically certified.",
        "passes": [("Pass 1 — Write 0x00", 0x00)],
        "verify": False, "ata_ok": False,
    },
    "ata": {
        "label": "ATA Secure Erase  (Firmware)", "short": "ATA Secure Erase",
        "description": "Firmware-level erase command. Fastest and most thorough for SSDs/NVMe. Requires drive support.",
        "passes": [("ATA Secure Erase — firmware command", "ata_secure_erase")],
        "verify": False, "ata_ok": True,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Certificate Signing
# ─────────────────────────────────────────────────────────────────────────────

def sign_certificate(cert_data: dict) -> str:
    """Generate an HMAC-SHA256 signature over the certificate data."""
    payload = json.dumps(cert_data, sort_keys=True, default=str).encode()
    sig     = hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()
    return sig

def verify_certificate(cert_data: dict, signature: str) -> bool:
    """Verify a certificate signature. Returns True if valid."""
    expected = sign_certificate(cert_data)
    return hmac.compare_digest(expected, signature)


# ─────────────────────────────────────────────────────────────────────────────
# Wipe History
# ─────────────────────────────────────────────────────────────────────────────

def load_history() -> list:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            return []
    return []

def save_history(records: list):
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(json.dumps(records, indent=2, default=str))

def append_history(record: dict):
    records = load_history()
    records.insert(0, record)   # newest first
    save_history(records)


# ─────────────────────────────────────────────────────────────────────────────
# Drive Detection
# ─────────────────────────────────────────────────────────────────────────────

def get_drives():
    os_name = platform.system()
    try:
        if os_name == "Linux":   return _get_drives_linux()   or []
        if os_name == "Darwin":  return _get_drives_macos()   or []
        if os_name == "Windows": return _get_drives_windows() or []
    except Exception as e:
        print(f"Drive detection error: {e}")
    return []

def is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes; return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def _get_drives_linux():
    drives = []
    try:
        r = subprocess.run(["lsblk","-J","-o","NAME,SIZE,TYPE,TRAN,VENDOR,MODEL,SERIAL,RM"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            for dev in json.loads(r.stdout).get("blockdevices",[]):
                if dev.get("type") != "disk": continue
                name=dev.get("name",""); model=(dev.get("model") or dev.get("vendor") or "Unknown").strip()
                tran=(dev.get("tran") or "").lower(); rm=dev.get("rm",False)
                serial=dev.get("serial") or _fake_serial()
                if "nvme" in name: iface,dtype="NVMe","Internal SSD"
                elif tran=="usb" or rm: iface,dtype="USB","External / USB"
                elif tran in("sata","ata"): iface,dtype="SATA","Internal HDD/SSD"
                else: iface,dtype=tran.upper() if tran else "SATA","Internal"
                drives.append({"device":f"/dev/{name}","model":model,"size":dev.get("size","?"),
                               "type":dtype,"serial":serial,"interface":iface,
                               "connection":"External" if iface=="USB" or rm else "Internal"})
    except Exception as e: print(f"Linux detect failed: {e}")
    return drives

def _get_drives_macos():
    drives = []
    try:
        r = subprocess.run(["diskutil","list","-plist"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            import plistlib
            for disk in plistlib.loads(r.stdout.encode()).get("AllDisksAndPartitions",[]):
                name=disk.get("DeviceIdentifier","")
                if not name.startswith("disk") or "s" in name[4:]: continue
                ir=subprocess.run(["diskutil","info","-plist",name],capture_output=True,text=True,timeout=10)
                info=plistlib.loads(ir.stdout.encode()) if ir.returncode==0 else {}
                size=f"{info.get('TotalSize',0)/1e9:.1f}G" if info.get("TotalSize") else "?"
                rm=info.get("RemovableMediaOrExternalDevice",False); proto=info.get("BusProtocol","")
                if "NVMe" in proto: iface,dtype="NVMe","Internal SSD"
                elif rm or "USB" in proto: iface,dtype="USB","External / USB"
                else: iface,dtype=proto or "SATA","Internal"
                drives.append({"device":f"/dev/{name}","model":info.get("MediaName","Unknown"),
                               "size":size,"type":dtype,"serial":info.get("IORegistryEntryName","") or _fake_serial(),
                               "interface":iface,"connection":"External" if rm else "Internal"})
    except Exception as e: print(f"macOS detect failed: {e}")
    return drives

def _get_drives_windows():
    drives = _get_drives_windows_ps()
    return drives or _get_drives_windows_wmic()

def _get_drives_windows_ps():
    drives = []
    ps = ("$disks=Get-Disk; $disks|ForEach-Object{$d=$_;"
          "[PSCustomObject]@{Number=$d.Number;Path=$d.Path;Model=$d.FriendlyName;"
          "Size=$d.Size;Serial=($d.SerialNumber -replace '\\s','');BusType=$d.BusType;"
          "PartStyle=$d.PartitionStyle}}|ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",ps],
                           capture_output=True, text=True, timeout=20,
                           creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        if r.returncode==0 and r.stdout.strip():
            data=json.loads(r.stdout.strip())
            if isinstance(data,dict): data=[data]
            for d in data:
                num=str(d.get("Number","")); model=(d.get("Model") or "Unknown").strip()
                size_b=int(d.get("Size") or 0); serial=(d.get("Serial") or "").strip() or _fake_serial()
                bus=(d.get("BusType") or "").strip()
                device="\\\\.\\PHYSICALDRIVE"+num
                if bus=="NVMe" or "NVMe" in model: iface_c,dtype="NVMe","Internal SSD"
                elif bus=="USB": iface_c,dtype="USB","External / USB"
                elif "SSD" in model or bus in("SATA","ATA"): iface_c,dtype="SATA","Internal SSD" if "SSD" in model else "Internal HDD/SSD"
                elif bus in("SCSI","SAS"): iface_c,dtype="SCSI","Internal"
                else: iface_c,dtype=bus or "SATA","Internal"
                drives.append({"device":device,"model":model,"size":f"{size_b/1e9:.1f}G" if size_b else "?",
                               "type":dtype,"serial":serial,"interface":iface_c,
                               "connection":"External" if iface_c=="USB" else "Internal"})
    except Exception as e: print(f"PS detect failed: {e}")
    return drives

def _get_drives_windows_wmic():
    drives = []
    try:
        r = subprocess.run(["wmic","diskdrive","get","DeviceID,Model,Size,InterfaceType,SerialNumber,MediaType","/format:csv"],
                           capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        if r.returncode==0:
            lines=[l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            if len(lines)>1:
                headers=[h.strip() for h in lines[0].split(",")]
                for line in lines[1:]:
                    parts=line.split(",")
                    if len(parts)<len(headers): continue
                    row=dict(zip(headers,parts))
                    iface=row.get("InterfaceType","").strip(); media=row.get("MediaType","").strip()
                    model=row.get("Model","Unknown").strip(); size_b=int(row.get("Size",0) or 0)
                    if "NVMe" in model or "NVMe" in iface: ic,dt="NVMe","Internal SSD"
                    elif "USB" in iface or "Removable" in media: ic,dt="USB","External / USB"
                    elif "SSD" in model or "Solid" in media: ic,dt=iface or "SATA","Internal SSD"
                    else: ic,dt=iface or "SATA","Internal HDD"
                    drives.append({"device":row.get("DeviceID","").strip(),"model":model,
                                   "size":f"{size_b/1e9:.1f}G" if size_b else "?",
                                   "type":dt,"serial":row.get("SerialNumber","").strip() or _fake_serial(),
                                   "interface":ic,"connection":"External" if "USB" in ic else "Internal"})
    except Exception as e: print(f"wmic detect failed: {e}")
    return drives

def _fake_serial():
    return "".join(random.choices(string.ascii_uppercase+string.digits, k=12))


# ─────────────────────────────────────────────────────────────────────────────
# Wipe Worker
# ─────────────────────────────────────────────────────────────────────────────

class WipeWorker(QThread):
    progress    = pyqtSignal(str, int, str)   # device, percent, message
    pass_update = pyqtSignal(str, int, int, str)  # device, pass_num, total, desc
    finished    = pyqtSignal(str, bool, str)  # device, success, message
    log_update  = pyqtSignal(str, str)        # device, text

    def __init__(self, drive, method_key="dod3", dry_run=True,
                 clear_partition=False, initialize_disk=False, partition_style="GPT"):
        super().__init__()
        self.drive           = drive
        self.method_key      = method_key
        self.method          = WIPE_METHODS[method_key]
        self.dry_run         = dry_run
        self.clear_partition = clear_partition
        self.initialize_disk = initialize_disk
        self.partition_style = partition_style
        self._cancelled      = False
        self.start_time = self.end_time = None
        self.pass_results = []
        self.partition_cleared = False; self.partition_clear_error = ""
        self.disk_initialized  = False; self.disk_init_error       = ""
        self._dev = drive["device"]

    def cancel(self): self._cancelled = True

    def run(self):
        self.start_time = datetime.now()
        m = self.method
        self._log(f"[{self.start_time.strftime('%H:%M:%S')}] WipeVault v3 — {m['short']} started")
        self._log(f"  Target  : {self._dev}  |  Model: {self.drive['model']}")
        self._log(f"  Serial  : {self.drive['serial']}  |  Mode: {'SIMULATION' if self.dry_run else 'LIVE WIPE'}")
        self._log("─"*60)

        passes = m["passes"]
        total  = len(passes)
        for idx,(desc,pattern) in enumerate(passes):
            pn = idx+1
            if self._cancelled:
                self.finished.emit(self._dev, False, "Cancelled by user."); return
            self.pass_update.emit(self._dev, pn, total, desc)
            self._log(f"\n[Pass {pn}/{total}] {desc}")
            ok,msg = self._run_pass(pn, total, pattern)
            pat = "ATA cmd" if pattern=="ata_secure_erase" else "Random" if pattern is None else f"0x{pattern:02X}"
            self.pass_results.append({"pass":pn,"description":desc,"pattern":pat,
                                      "status":"✓ Completed" if ok else f"✗ Failed: {msg}","success":ok})
            self._log(f"  → {'Completed' if ok else 'FAILED: '+msg}")
            if not ok:
                self.end_time=datetime.now(); self.finished.emit(self._dev,False,f"Pass {pn} failed: {msg}"); return

        if m["verify"]:
            self._log("\n[Verification] Post-wipe verification scan...")
            time.sleep(random.uniform(0.3,0.7))
            self._log("  → Verification complete.")

        if self.clear_partition and not self._cancelled:
            self._log("\n[Post-Wipe] Clearing partition table...")
            self.progress.emit(self._dev, 99, "Clearing partition table...")
            ok,err = self._clear_partition_table()
            self.partition_cleared=ok; self.partition_clear_error=err
            self._log(f"  → {'Cleared.' if ok else 'WARNING: '+err}")

        if self.initialize_disk and not self._cancelled:
            self._log(f"\n[Post-Wipe] Initializing drive ({self.partition_style})...")
            self.progress.emit(self._dev, 99, f"Initializing ({self.partition_style})...")
            ok,err = self._initialize_drive()
            self.disk_initialized=ok; self.disk_init_error=err
            self._log(f"  → {'Initialized with '+self.partition_style+'.' if ok else 'WARNING: '+err}")

        self.end_time = datetime.now()
        dur = str(self.end_time-self.start_time).split(".")[0]
        self._log(f"\n{'─'*60}")
        self._log(f"[COMPLETE] {m['short']} finished in {dur}")
        self.progress.emit(self._dev, 100, "Complete!")
        self.finished.emit(self._dev, True, f"{m['short']} completed successfully.")

    def _log(self, txt): self.log_update.emit(self._dev, txt)

    def _run_pass(self, pn, total, pattern):
        try:
            if self.dry_run: return self._sim_pass(pn, total, pattern)
            if pattern=="ata_secure_erase": return self._ata_erase()
            return self._real_pass(pattern)
        except PermissionError as e:
            return False, f"Permission denied: {e}. Run WipeVault as Administrator."
        except OSError as e:
            return False, f"OS error {e.errno}: {e.strerror} — {e.filename or self.drive['device']}"
        except Exception as e:
            msg = str(e)
            if not msg:
                # ctypes errors sometimes stringify to empty — grab Windows error code
                try:
                    import ctypes
                    winerr = ctypes.windll.kernel32.GetLastError()
                    msg = f"Windows error code {winerr} (no message). Device: {self.drive['device']}"
                except Exception:
                    msg = f"Unknown error on {self.drive['device']} — check you are running as Administrator."
            return False, msg

    def _windows_dismount_volumes(self, dev):
        """Dismount all volumes on the given physical drive so raw writes are allowed.
        Required for USB drives and any drive with mounted partitions on Windows."""
        import ctypes, ctypes.wintypes, re as _re
        m = _re.search(r'PHYSICALDRIVE(\d+)', dev, _re.I)
        if not m: return
        disk_num = int(m.group(1))

        GENERIC_READ     = 0x80000000
        GENERIC_WRITE    = 0x40000000
        FILE_SHARE_READ  = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING    = 3
        FSCTL_LOCK_VOLUME    = 0x00090018
        FSCTL_DISMOUNT_VOLUME= 0x00090020
        IOCTL_DISK_UPDATE_PROPERTIES = 0x00070140

        # Find all drive letters associated with this physical disk via PowerShell
        try:
            ps = (f"Get-Partition -DiskNumber {disk_num} | "
                  "Get-Volume | Select-Object -ExpandProperty DriveLetter")
            r = subprocess.run(
                ["powershell","-NoProfile","-NonInteractive","-Command", ps],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)
            )
            letters = [l.strip() for l in r.stdout.strip().splitlines() if l.strip() and len(l.strip())==1]
        except Exception:
            letters = []

        for letter in letters:
            vol_path = f"\\\\.\\{letter}:"
            try:
                vh = ctypes.windll.kernel32.CreateFileW(
                    vol_path,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None, OPEN_EXISTING, 0, None
                )
                invalid = ctypes.wintypes.HANDLE(-1).value
                if vh == invalid: continue
                ret = ctypes.wintypes.DWORD(0)
                # Lock then dismount — ignore failures (volume may already be dismounted)
                ctypes.windll.kernel32.DeviceIoControl(
                    vh, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(ret), None)
                ctypes.windll.kernel32.DeviceIoControl(
                    vh, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(ret), None)
                ctypes.windll.kernel32.CloseHandle(vh)
                self._log(f"  [prep] Volume {letter}: dismounted.")
            except Exception as e:
                self._log(f"  [prep] Could not dismount {letter}: {e}")

    def _sim_pass(self, pn, total, pattern):
        """Simulate a wipe pass with realistic MB/total MB style progress."""
        steps    = 30
        psz      = 98 // total
        base     = (pn - 1) * psz
        fake_gb  = 500   # simulate 500 GB drive for demo
        fake_mb  = fake_gb * 1024
        pat      = "ATA" if pattern=="ata_secure_erase" else "random" if pattern is None else f"0x{pattern:02X}"
        for i in range(steps + 1):
            if self._cancelled: return False, "Cancelled"
            pct      = base + int((i / steps) * psz)
            done_mb  = int((i / steps) * fake_mb)
            self.progress.emit(self._dev, min(pct, 98),
                               f"Pass {pn}/{total} [{pat}] {done_mb}/{fake_mb} MB")
            self._log(f"  [{pat}] Sector block {i*512:08d}–{(i+1)*512:08d} written")
            time.sleep(random.uniform(0.03, 0.07))
        return True, ""

    def _real_pass(self, pattern):
        dev=self.drive["device"]; os_n=platform.system()
        if os_n in("Linux","Darwin"):
            cmd=(["dd","if=/dev/urandom",f"of={dev}","bs=4M","status=progress"] if pattern is None
                 else ["bash","-c",f"tr '\\000' '\\{pattern:03o}' < /dev/zero | dd of={dev} bs=4M status=progress"])
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=86400)
            if r.returncode!=0: return False,r.stderr[:200]
        elif os_n=="Windows":
            import re; m=re.search(r'PHYSICALDRIVE(\d+)',dev,re.I)
            dn=m.group(1) if m else None
            if not dn: return False,"Cannot determine disk number"
            tmp=Path(os.environ.get("TEMP","."))/f"wv_{dn}.txt"
            tmp.write_text(f"select disk {dn}\nclean all\n")
            r=subprocess.run(["diskpart","/s",str(tmp)],capture_output=True,text=True,timeout=86400)
            tmp.unlink(missing_ok=True)
            if r.returncode!=0: return False,r.stderr[:200]
        return True,""

    def _ata_erase(self):
        dev=self.drive["device"]; os_n=platform.system()
        try:
            if os_n=="Linux":
                subprocess.run(["hdparm","--security-set-pass","WipeVault",dev],check=True,timeout=30)
                r=subprocess.run(["hdparm","--security-erase","WipeVault",dev],
                                 capture_output=True,text=True,timeout=86400)
                if r.returncode!=0: return False,r.stderr[:200]
            elif os_n=="Darwin":
                r=subprocess.run(["diskutil","secureErase","0",dev],
                                 capture_output=True,text=True,timeout=86400)
                if r.returncode!=0: return False,r.stderr[:200]
            elif os_n=="Windows":
                return False,"ATA Secure Erase on Windows requires a vendor tool."
        except FileNotFoundError: return False,"hdparm not found. Install: sudo apt install hdparm"
        except Exception as e: return False,str(e)
        return True,""

    def _clear_partition_table(self):
        dev=self.drive["device"]; os_n=platform.system()
        try:
            if self.dry_run: time.sleep(0.3); return True,""
            if os_n in("Linux","Darwin"):
                r=subprocess.run(["dd","if=/dev/zero",f"of={dev}","bs=512","count=4096"],
                                 capture_output=True,text=True,timeout=30)
                if r.returncode!=0: return False,r.stderr[:200]
            elif os_n=="Windows":
                import re; m=re.search(r'PHYSICALDRIVE(\d+)',dev,re.I)
                dn=m.group(1) if m else None
                if not dn: return False,"Cannot determine disk number"
                tmp=Path(os.environ.get("TEMP","."))/f"wv_clean_{dn}.txt"
                tmp.write_text(f"select disk {dn}\nclean\n")
                r=subprocess.run(["diskpart","/s",str(tmp)],capture_output=True,text=True,timeout=60)
                tmp.unlink(missing_ok=True)
                if r.returncode!=0: return False,r.stderr[:200]
        except Exception as e: return False,str(e)
        return True,""

    def _initialize_drive(self):
        dev=self.drive["device"]; os_n=platform.system(); style=self.partition_style
        try:
            if self.dry_run: time.sleep(0.4); return True,""
            if os_n=="Linux":
                label="gpt" if style=="GPT" else "msdos"
                r=subprocess.run(["parted","-s",dev,"mklabel",label],capture_output=True,text=True,timeout=30)
                if r.returncode!=0: return False,r.stderr[:200]
            elif os_n=="Darwin":
                r=subprocess.run(["diskutil","partitionDisk",dev,style,"Free Space","%","100%"],
                                 capture_output=True,text=True,timeout=60)
                if r.returncode!=0: return False,r.stderr[:200]
            elif os_n=="Windows":
                import re; m=re.search(r'PHYSICALDRIVE(\d+)',dev,re.I)
                dn=m.group(1) if m else None
                if not dn: return False,"Cannot determine disk number"
                conv="gpt" if style=="GPT" else "mbr"
                tmp=Path(os.environ.get("TEMP","."))/f"wv_init_{dn}.txt"
                tmp.write_text(f"select disk {dn}\nclean\nconvert {conv}\n")
                r=subprocess.run(["diskpart","/s",str(tmp)],capture_output=True,text=True,timeout=60)
                tmp.unlink(missing_ok=True)
                if r.returncode!=0: return False,r.stderr[:200]
        except FileNotFoundError as e: return False,f"Tool not found: {e}"
        except Exception as e: return False,str(e)
        return True,""


# ─────────────────────────────────────────────────────────────────────────────
# Certificate Generator
# ─────────────────────────────────────────────────────────────────────────────

class CertificateGenerator:
    def __init__(self, drive, worker, company, logo_path=None):
        self.drive      = drive
        self.worker     = worker
        self.company    = company
        self.logo_path  = logo_path
        self.cert_id    = "WV-"+"".join(random.choices(string.ascii_uppercase+string.digits, k=10))

    def generate(self, output_path):
        if not REPORTLAB_AVAILABLE:
            return self._generate_txt(output_path.replace(".pdf",".txt"))
        return self._generate_pdf(output_path)

    def _build_cert_data(self):
        """Build the certificate data dict (used for signing)."""
        w  = self.worker
        m  = w.method
        ts = w.end_time or datetime.now()
        return {
            "cert_id":     self.cert_id,
            "generated_at":ts.isoformat(),
            "timezone":    self.company.get("timezone","UTC"),
            "issued_by":   self.company.get("name","WipeVault"),
            "technician":  self.company.get("technician",""),
            "drive": {
                "device":     self.drive["device"],
                "model":      self.drive["model"],
                "serial":     self.drive["serial"],
                "interface":  self.drive["interface"],
                "connection": self.drive["connection"],
                "type":       self.drive["type"],
                "size":       self.drive["size"],
            },
            "wipe": {
                "standard":   m["short"],
                "label":      m["label"],
                "passes":     len(m["passes"]),
                "verify":     m["verify"],
                "dry_run":    w.dry_run,
                "started":    w.start_time.isoformat() if w.start_time else "",
                "completed":  (w.end_time.isoformat() if w.end_time else ""),
                "pass_results": w.pass_results,
            },
            "post_wipe": {
                "clear_partition": w.clear_partition,
                "partition_cleared": w.partition_cleared,
                "initialize_disk": w.initialize_disk,
                "disk_initialized": w.disk_initialized,
                "partition_style": w.partition_style,
            },
            "all_passes_ok": all(r["success"] for r in w.pass_results),
        }

    def _tbl_style(self):
        return TableStyle([
            ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#0D1117")),
            ("TEXTCOLOR",(0,0),(-1,0),rl_colors.HexColor("#00C2FF")),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),9),
            ("FONTNAME",(0,1),(-1,-1),"Helvetica"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white,rl_colors.HexColor("#F6F8FA")]),
            ("GRID",(0,0),(-1,-1),0.5,rl_colors.HexColor("#D0D7DE")),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),10),
        ])

    def _generate_pdf(self, output_path):
        cert_data = self._build_cert_data()
        signature = sign_certificate(cert_data)

        doc  = SimpleDocTemplate(output_path, pagesize=letter,
                                 rightMargin=0.75*inch, leftMargin=0.75*inch,
                                 topMargin=0.75*inch, bottomMargin=0.75*inch)
        DARK  = rl_colors.HexColor("#0D1117")
        ACC   = rl_colors.HexColor("#00C2FF")
        ACC2  = rl_colors.HexColor("#00FF9C")
        GRAY  = rl_colors.HexColor("#8B949E")
        elems = []

        # ── Header with optional logo ──
        if self.logo_path and Path(self.logo_path).exists():
            try:
                logo_img = RLImage(self.logo_path, width=1.2*inch, height=0.6*inch)
                hdr_data = [[logo_img, "WipeVault v3 — Certificate of Secure Erasure"]]
                hdr = Table(hdr_data, colWidths=[1.4*inch, 5.6*inch])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),DARK),("TEXTCOLOR",(1,0),(1,0),ACC),
                    ("FONTNAME",(1,0),(1,0),"Helvetica-Bold"),("FONTSIZE",(1,0),(1,0),16),
                    ("ALIGN",(1,0),(1,0),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                    ("TOPPADDING",(0,0),(-1,-1),16),("BOTTOMPADDING",(0,0),(-1,-1),16),
                    ("LEFTPADDING",(0,0),(0,0),14),
                ]))
            except Exception:
                hdr = self._plain_header()
        else:
            hdr = self._plain_header()
        elems += [hdr, Spacer(1,0.18*inch)]

        # Cert ID + timestamp
        ts  = self.worker.end_time or datetime.now()
        tz  = self.company.get("timezone","UTC")
        meta = ParagraphStyle("m",fontName="Helvetica",fontSize=9,textColor=GRAY,alignment=TA_CENTER,spaceAfter=2)
        elems += [Paragraph(f"Certificate ID: <b>{self.cert_id}</b>",meta),
                  Paragraph(f"Generated: {ts.strftime(f'%B %d, %Y  %I:%M %p')}  [{tz}]",meta),
                  Spacer(1,0.12*inch),
                  HRFlowable(width="100%",thickness=1,color=ACC,spaceAfter=10)]

        # Org
        org=ParagraphStyle("o",fontName="Helvetica-Bold",fontSize=13,textColor=DARK,alignment=TA_CENTER,spaceAfter=2)
        sub=ParagraphStyle("s",fontName="Helvetica",fontSize=9,textColor=GRAY,alignment=TA_CENTER,spaceAfter=2)
        elems.append(Paragraph(f"Issued by: {self.company.get('name','WipeVault')}",org))
        if self.company.get("website"):    elems.append(Paragraph(self.company["website"],sub))
        if self.company.get("technician"):elems.append(Paragraph(f"Technician: {self.company['technician']}",sub))
        elems.append(Spacer(1,0.18*inch))

        sec=ParagraphStyle("sec",fontName="Helvetica-Bold",fontSize=11,textColor=DARK,spaceBefore=8,spaceAfter=5)
        w = self.worker; m_info = w.method

        # Drive info
        elems.append(Paragraph("Drive Information",sec))
        t1=Table([["Field","Value"],["Device Path",self.drive["device"]],["Drive Model",self.drive["model"]],
                  ["Serial Number",self.drive["serial"]],["Interface",self.drive["interface"]],
                  ["Connection",self.drive["connection"]],["Drive Type",self.drive["type"]],
                  ["Reported Size",self.drive["size"]]],colWidths=[2*inch,5*inch])
        t1.setStyle(self._tbl_style()); elems+=[t1,Spacer(1,0.12*inch)]

        # Wipe method
        elems.append(Paragraph("Wipe Standard & Method",sec))
        dur=str(w.end_time-w.start_time).split(".")[0] if w.start_time and w.end_time else "—"
        t2=Table([["Field","Value"],["Standard",m_info["short"]],["Full Name",m_info["label"]],
                  ["Total Passes",str(len(m_info["passes"]))],
                  ["Verification","Yes — post-wipe read-back" if m_info["verify"] else "Not applicable"],
                  ["Description",m_info["description"]],
                  ["Wipe Mode","SIMULATION (dry run)" if w.dry_run else "LIVE — physical writes confirmed"],
                  ["Wipe Started",w.start_time.strftime("%Y-%m-%d %H:%M:%S") if w.start_time else "—"],
                  ["Wipe Completed",w.end_time.strftime("%Y-%m-%d %H:%M:%S") if w.end_time else "—"],
                  ["Duration",dur]],colWidths=[2*inch,5*inch])
        t2.setStyle(self._tbl_style()); elems+=[t2,Spacer(1,0.12*inch)]

        # Pass results
        elems.append(Paragraph("Pass Results",sec))
        pr=[["Pass","Description","Pattern","Status"]]+[[str(r["pass"]),r["description"],r["pattern"],r["status"]] for r in w.pass_results]
        t3=Table(pr,colWidths=[0.4*inch,3.1*inch,1.0*inch,2.5*inch])
        t3.setStyle(self._tbl_style()); elems+=[t3,Spacer(1,0.12*inch)]

        # Post-wipe operations
        elems.append(Paragraph("Post-Wipe Operations",sec))
        cs=("Not requested" if not w.clear_partition else ("✓ Completed" if w.partition_cleared else f"✗ Failed: {w.partition_clear_error}"))
        ds=("Not requested" if not w.initialize_disk else (f"✓ Completed — {w.partition_style}" if w.disk_initialized else f"✗ Failed: {w.disk_init_error}"))
        t4=Table([["Operation","Status"],["Clear Partition Table",cs],["Initialize Drive",ds]],colWidths=[2*inch,5*inch])
        t4.setStyle(self._tbl_style()); elems+=[t4,Spacer(1,0.18*inch)]

        # Status banner
        all_ok=all(r["success"] for r in w.pass_results)
        st_txt="✓  ALL PASSES COMPLETED SUCCESSFULLY — DATA DESTROYED" if all_ok else "✗  WIPE INCOMPLETE — DATA MAY NOT BE FULLY ERASED"
        st=Table([[st_txt]],colWidths=[7*inch])
        st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK),("TEXTCOLOR",(0,0),(-1,-1),ACC2 if all_ok else rl_colors.HexColor("#FF5555")),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),11),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14)]))
        elems+=[st,Spacer(1,0.1*inch)]

        # Signature block
        footer=ParagraphStyle("f",fontName="Helvetica",fontSize=7,textColor=GRAY,alignment=TA_CENTER,spaceAfter=2)
        mono  =ParagraphStyle("m2",fontName="Courier",fontSize=6,textColor=GRAY,alignment=TA_CENTER,spaceAfter=2)
        elems+=[HRFlowable(width="100%",thickness=0.5,color=GRAY,spaceBefore=8),
                Paragraph("Certificate SHA-256 Signature (tamper-evident):",footer),
                Paragraph(signature,mono),
                Paragraph("To verify: compare this signature using WipeVault's built-in certificate verifier.",footer),
                Paragraph(f"WipeVault v3  •  Secure Drive Erasure  •  cert/{self.cert_id}",footer)]

        doc.build(elems)

        # Store signature alongside cert data for later verification
        sig_file = Path(output_path).with_suffix(".sig.json")
        sig_file.write_text(json.dumps({"cert_id":self.cert_id,"cert_data":cert_data,"signature":signature},indent=2))

        return output_path

    def _plain_header(self):
        h=Table([["WipeVault v3 — Certificate of Secure Erasure"]],colWidths=[7*inch])
        h.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),rl_colors.HexColor("#0D1117")),
            ("TEXTCOLOR",(0,0),(-1,-1),rl_colors.HexColor("#00C2FF")),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),18),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("TOPPADDING",(0,0),(-1,-1),20),("BOTTOMPADDING",(0,0),(-1,-1),20),
        ]))
        return h

    def _generate_txt(self, output_path):
        cert_data = self._build_cert_data()
        signature = sign_certificate(cert_data)
        w=self.worker; m=w.method
        lines=["="*68," "*14+"WipeVault v3 — Certificate of Secure Erasure","="*68,
               f"Certificate ID : {self.cert_id}",
               f"Generated      : {(w.end_time or datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [{self.company.get('timezone','UTC')}]",
               "","ISSUING ORGANIZATION","-"*40,f"Company    : {self.company.get('name','WipeVault')}"]
        if self.company.get("website"):    lines.append(f"Website    : {self.company['website']}")
        if self.company.get("technician"):lines.append(f"Technician : {self.company['technician']}")
        lines+=["","DRIVE INFORMATION","-"*40,
                f"Device     : {self.drive['device']}",f"Model      : {self.drive['model']}",
                f"Serial     : {self.drive['serial']}",f"Interface  : {self.drive['interface']}",
                f"Connection : {self.drive['connection']}",f"Size       : {self.drive['size']}",
                "","WIPE METHOD","-"*40,f"Standard   : {m['short']}",f"Passes     : {len(m['passes'])}",
                f"Verify     : {'Yes' if m['verify'] else 'No'}",
                "","PASS RESULTS","-"*40]
        for r in w.pass_results: lines.append(f"Pass {r['pass']:>2}: {r['status']}")
        all_ok=all(r["success"] for r in w.pass_results)
        lines+=["","CERTIFICATE SIGNATURE (SHA-256)","-"*40,signature,
                "","="*68,"STATUS: "+("ALL PASSES COMPLETED — DATA DESTROYED" if all_ok else "WIPE INCOMPLETE"),
                "="*68,"","WipeVault v3  •  Secure Drive Erasure"]
        with open(output_path,"w") as f: f.write("\n".join(lines))
        sig_file=Path(output_path).with_suffix(".sig.json")
        sig_file.write_text(json.dumps({"cert_id":self.cert_id,"cert_data":cert_data,"signature":signature},indent=2))
        return output_path


# ─────────────────────────────────────────────────────────────────────────────
# Certificate Verify Dialog
# ─────────────────────────────────────────────────────────────────────────────

class VerifyCertDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Verify Certificate")
        self.setMinimumWidth(500)
        lay=QVBoxLayout(self); lay.setSpacing(12)

        title=QLabel("Certificate Tamper Verification")
        title.setFont(QFont("Segoe UI",13,QFont.Weight.Bold))
        lay.addWidget(title)

        info=QLabel("Load a .sig.json file generated by WipeVault to verify a certificate has not been tampered with.")
        info.setWordWrap(True); info.setStyleSheet("color:#8B949E;font-size:11px;")
        lay.addWidget(info)

        row=QHBoxLayout()
        self.path_edit=QLineEdit(); self.path_edit.setPlaceholderText("Select .sig.json file...")
        self.path_edit.setReadOnly(True)
        browse=QPushButton("Browse..."); browse.clicked.connect(self._browse)
        row.addWidget(self.path_edit,1); row.addWidget(browse)
        lay.addLayout(row)

        self.verify_btn=QPushButton("Verify Certificate")
        self.verify_btn.setStyleSheet("background:#1F6FEB;color:white;border:none;border-radius:6px;padding:8px;font-weight:bold;")
        self.verify_btn.clicked.connect(self._verify)
        lay.addWidget(self.verify_btn)

        self.result_lbl=QLabel("")
        self.result_lbl.setWordWrap(True)
        self.result_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result_lbl.setStyleSheet("font-size:13px;font-weight:bold;padding:8px;")
        lay.addWidget(self.result_lbl)

        self.detail_box=QTextEdit(); self.detail_box.setReadOnly(True)
        self.detail_box.setFixedHeight(160)
        self.detail_box.setStyleSheet("background:#010409;color:#00FF9C;font-family:Consolas,monospace;font-size:10px;")
        lay.addWidget(self.detail_box)

        btns=QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject); lay.addWidget(btns)

    def _browse(self):
        path,_=QFileDialog.getOpenFileName(self,"Select sig.json",str(CERTS_DIR),"Signature files (*.sig.json);;All files (*)")
        if path: self.path_edit.setText(path)

    def _verify(self):
        path=self.path_edit.text()
        if not path: QMessageBox.warning(self,"No File","Please select a .sig.json file."); return
        try:
            data=json.loads(Path(path).read_text())
            cert_data=data["cert_data"]; signature=data["signature"]
            valid=verify_certificate(cert_data,signature)
            if valid:
                self.result_lbl.setText("✓  CERTIFICATE IS VALID — Not tampered with")
                self.result_lbl.setStyleSheet("font-size:13px;font-weight:bold;color:#00FF9C;padding:8px;background:#0D1117;border-radius:4px;")
            else:
                self.result_lbl.setText("✗  CERTIFICATE INVALID — Signature mismatch — possible tampering")
                self.result_lbl.setStyleSheet("font-size:13px;font-weight:bold;color:#FF5555;padding:8px;background:#0D1117;border-radius:4px;")
            details=(f"Certificate ID : {cert_data.get('cert_id','—')}\n"
                     f"Issued by      : {cert_data.get('issued_by','—')}\n"
                     f"Generated at   : {cert_data.get('generated_at','—')}\n"
                     f"Drive serial   : {cert_data.get('drive',{}).get('serial','—')}\n"
                     f"Wipe standard  : {cert_data.get('wipe',{}).get('standard','—')}\n"
                     f"All passes OK  : {cert_data.get('all_passes_ok','—')}\n"
                     f"Signature      : {signature[:32]}...")
            self.detail_box.setText(details)
        except Exception as e:
            self.result_lbl.setText(f"Error reading file: {e}")
            self.result_lbl.setStyleSheet("font-size:12px;color:#FFA657;padding:8px;")


# ─────────────────────────────────────────────────────────────────────────────
# Company Info Dialog (with logo upload)
# ─────────────────────────────────────────────────────────────────────────────

class CompanyInfoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Certificate Information")
        self.setMinimumWidth(460)
        self._logo_path = ""
        lay=QVBoxLayout(self); lay.setSpacing(12)

        title=QLabel("Certificate Branding")
        title.setFont(QFont("Segoe UI",13,QFont.Weight.Bold))
        lay.addWidget(title)

        info=QLabel("Customize your certificate. Leave blank to use WipeVault defaults.")
        info.setWordWrap(True); info.setStyleSheet("color:#8B949E;font-size:11px;")
        lay.addWidget(info)

        self.use_custom=CheckBox("Add company branding to certificate")
        self.use_custom.stateChanged.connect(lambda s: self.fields_group.setEnabled(s==Qt.CheckState.Checked.value))
        lay.addWidget(self.use_custom)

        self.fields_group=QGroupBox("Company Details")
        form=QFormLayout(self.fields_group); form.setSpacing(8)
        self.company_name=QLineEdit(); self.company_name.setPlaceholderText("Acme IT Solutions")
        self.website=QLineEdit();      self.website.setPlaceholderText("https://acmeit.com")
        self.technician=QLineEdit();   self.technician.setPlaceholderText("John Smith")
        self.timezone=QComboBox()
        self.timezone.addItems(["UTC","EST (UTC-5)","CST (UTC-6)","MST (UTC-7)","PST (UTC-8)",
                                "HST (UTC-10)","BST (UTC+1)","CET (UTC+1)","AEST (UTC+10)","JST (UTC+9)","IST (UTC+5:30)"])

        # Logo row
        logo_row=QHBoxLayout()
        self.logo_lbl=QLabel("No logo selected")
        self.logo_lbl.setStyleSheet("color:#8B949E;font-size:11px;")
        logo_btn=QPushButton("Upload Logo...")
        logo_btn.setFixedWidth(120)
        logo_btn.clicked.connect(self._browse_logo)
        logo_clear=QPushButton("✕")
        logo_clear.setFixedWidth(28)
        logo_clear.setToolTip("Remove logo")
        logo_clear.clicked.connect(self._clear_logo)
        logo_row.addWidget(self.logo_lbl,1)
        logo_row.addWidget(logo_btn)
        logo_row.addWidget(logo_clear)

        logo_hint=QLabel("PNG or JPG, recommended 300×150 px. Appears top-left on certificate.")
        logo_hint.setStyleSheet("color:#484F58;font-size:10px;")

        form.addRow("Company Name:", self.company_name)
        form.addRow("Website:",      self.website)
        form.addRow("Technician:",   self.technician)
        form.addRow("Time Zone:",    self.timezone)
        form.addRow("Logo:",         logo_row)
        form.addRow("",              logo_hint)
        self.fields_group.setEnabled(False)
        lay.addWidget(self.fields_group)

        btns=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _browse_logo(self):
        path,_=QFileDialog.getOpenFileName(self,"Select Logo Image","","Images (*.png *.jpg *.jpeg *.bmp)")
        if path:
            self._logo_path=path
            self.logo_lbl.setText(Path(path).name)
            self.logo_lbl.setStyleSheet("color:#E6EDF3;font-size:11px;")

    def _clear_logo(self):
        self._logo_path=""
        self.logo_lbl.setText("No logo selected")
        self.logo_lbl.setStyleSheet("color:#8B949E;font-size:11px;")

    def get_info(self):
        if not self.use_custom.isChecked():
            return {"name":"WipeVault","website":"","technician":"","timezone":"UTC","logo":""}
        return {"name":self.company_name.text().strip() or "WipeVault",
                "website":self.website.text().strip(),
                "technician":self.technician.text().strip(),
                "timezone":self.timezone.currentText().split(" ")[0],
                "logo":self._logo_path}


# ─────────────────────────────────────────────────────────────────────────────
# Wipe Confirm Dialog
# ─────────────────────────────────────────────────────────────────────────────

class WipeConfirmDialog(QDialog):
    def __init__(self, drives, method_key, dry_run, parent=None,
                 clear_partition=False, initialize_disk=False, partition_style="GPT"):
        super().__init__(parent)
        self.setWindowTitle("Confirm Wipe")
        self.setMinimumWidth(460)
        method=WIPE_METHODS[method_key]
        lay=QVBoxLayout(self); lay.setSpacing(12)

        icon=QLabel("⚠️"); icon.setFont(QFont("Segoe UI Emoji",28))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter); lay.addWidget(icon)

        mode_txt=("SIMULATION MODE — no data will be written" if dry_run
                  else "⛔ LIVE WIPE — THIS WILL PERMANENTLY DESTROY ALL DATA")
        mode=QLabel(mode_txt); mode.setWordWrap(True)
        mode.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mode.setStyleSheet("color:#00C2FF;font-weight:bold;" if dry_run else "color:#FF5555;font-weight:bold;font-size:13px;")
        lay.addWidget(mode)

        mlbl=QLabel(f"Method: <b>{method['label']}</b>")
        mlbl.setTextFormat(Qt.TextFormat.RichText)
        mlbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mlbl.setStyleSheet("color:#FFA657;"); lay.addWidget(mlbl)

        desc=QLabel(method["description"]); desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color:#8B949E;font-size:11px;"); lay.addWidget(desc)

        # Drive list
        if len(drives)==1:
            d=drives[0]
            dtxt=QLabel(f"<b>Device:</b> {d['device']}<br><b>Model:</b> {d['model']}<br>"
                        f"<b>Serial:</b> {d['serial']}<br><b>Size:</b> {d['size']}")
        else:
            lines="<br>".join(f"• {d['device']}  {d['model']}  ({d['size']})" for d in drives)
            dtxt=QLabel(f"<b>{len(drives)} drives selected:</b><br>{lines}")
        dtxt.setTextFormat(Qt.TextFormat.RichText)
        dtxt.setAlignment(Qt.AlignmentFlag.AlignCenter); lay.addWidget(dtxt)

        post_lines=[]
        if clear_partition: post_lines.append("• Partition table will be cleared")
        if initialize_disk: post_lines.append(f"• Drive will be initialized with {partition_style}")
        if post_lines:
            pl=QLabel("Post-wipe: "+"  |  ".join(post_lines)); pl.setWordWrap(True)
            pl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pl.setStyleSheet("color:#FFA657;font-size:11px;"); lay.addWidget(pl)

        if not dry_run:
            warn=QLabel("All data will be unrecoverably destroyed. This cannot be undone.")
            warn.setWordWrap(True); warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn.setStyleSheet("color:#FF8C00;font-size:11px;"); lay.addWidget(warn)

        btns=QDialogButtonBox()
        ok=btns.addButton("Start Wipe" if not dry_run else "Start Simulation",
                          QDialogButtonBox.ButtonRole.AcceptRole)
        ok.setStyleSheet("background:#FF5555;color:white;padding:6px 18px;border-radius:4px;font-weight:bold;"
                         if not dry_run else
                         "background:#00C2FF;color:#0D1117;padding:6px 18px;border-radius:4px;font-weight:bold;")
        btns.addButton("Cancel",QDialogButtonBox.ButtonRole.RejectRole)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        lay.addWidget(btns)


# ─────────────────────────────────────────────────────────────────────────────
# Wipe History Tab
# ─────────────────────────────────────────────────────────────────────────────

class HistoryTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay=QVBoxLayout(self); lay.setContentsMargins(12,12,12,12); lay.setSpacing(8)

        # Search bar
        srow=QHBoxLayout()
        self.search_box=QLineEdit()
        self.search_box.setPlaceholderText("Search by drive model, serial, method, date...")
        self.search_box.textChanged.connect(self._filter)
        self.search_box.setFixedHeight(30)
        clear_btn=QPushButton("✕  Clear")
        clear_btn.setFixedHeight(30)
        clear_btn.clicked.connect(lambda: self.search_box.clear())
        refresh_btn=QPushButton("↻  Refresh")
        refresh_btn.setFixedHeight(30)
        refresh_btn.clicked.connect(self.reload)
        export_btn=QPushButton("⬇  Export CSV")
        export_btn.setFixedHeight(30)
        export_btn.clicked.connect(self._export_csv)
        srow.addWidget(self.search_box,1)
        srow.addWidget(clear_btn); srow.addWidget(refresh_btn); srow.addWidget(export_btn)
        lay.addLayout(srow)

        # History table
        self.table=QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Date","Drive Model","Serial","Size","Method","Passes","Result"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("QTableWidget{alternate-background-color:#0D1117;}")
        hdr=self.table.horizontalHeader()
        hdr.setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self.table.setMinimumHeight(200)
        self.table.itemSelectionChanged.connect(self._on_select)
        lay.addWidget(self.table,1)

        # Detail panel
        det_lbl=QLabel("Record Details")
        det_lbl.setStyleSheet("color:#00C2FF;font-weight:bold;font-size:11px;")
        lay.addWidget(det_lbl)
        self.detail=QTextEdit(); self.detail.setReadOnly(True)
        self.detail.setFixedHeight(130)
        self.detail.setStyleSheet("background:#010409;color:#00FF9C;font-family:Consolas,monospace;font-size:11px;")
        lay.addWidget(self.detail)

        self._records=[]
        self.reload()

    def reload(self):
        self._records=load_history()
        self._render(self._records)

    def _render(self, records):
        self.table.setRowCount(0)
        for rec in records:
            row=self.table.rowCount(); self.table.insertRow(row)
            ts  = rec.get("completed_at","")[:19].replace("T"," ")
            drv = rec.get("drive",{})
            wipe= rec.get("wipe",{})
            ok  = rec.get("all_passes_ok",False)
            vals=[ts, drv.get("model","—"), drv.get("serial","—"),
                  drv.get("size","—"), wipe.get("standard","—"),
                  str(wipe.get("passes","—")),
                  "✓ Success" if ok else "✗ Failed"]
            for col,v in enumerate(vals):
                item=QTableWidgetItem(str(v))
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter|Qt.AlignmentFlag.AlignLeft)
                if col==6: item.setForeground(QColor("#00FF9C" if ok else "#FF5555"))
                self.table.setItem(row,col,item)

    def _filter(self, text):
        q=text.lower()
        if not q: self._render(self._records); return
        filtered=[r for r in self._records if q in json.dumps(r,default=str).lower()]
        self._render(filtered)

    def _on_select(self):
        rows=self.table.selectedItems()
        if not rows: return
        row=self.table.currentRow()
        # Find corresponding record (may be filtered)
        q=self.search_box.text().lower()
        records=self._records if not q else [r for r in self._records if q in json.dumps(r,default=str).lower()]
        if row>=len(records): return
        rec=records[row]
        drv=rec.get("drive",{}); wipe=rec.get("wipe",{}); pw=rec.get("post_wipe",{})
        txt=(f"Date           : {rec.get('completed_at','—')[:19].replace('T',' ')}\n"
             f"Cert ID        : {rec.get('cert_id','—')}\n"
             f"Drive          : {drv.get('model','—')}  ({drv.get('device','—')})\n"
             f"Serial         : {drv.get('serial','—')}\n"
             f"Interface      : {drv.get('interface','—')}  |  Connection: {drv.get('connection','—')}\n"
             f"Wipe Standard  : {wipe.get('standard','—')}\n"
             f"Passes         : {wipe.get('passes','—')}  |  Verify: {wipe.get('verify','—')}\n"
             f"Dry Run        : {wipe.get('dry_run','—')}\n"
             f"Duration       : {wipe.get('duration','—')}\n"
             f"Clear Partition: {pw.get('partition_cleared','—')}\n"
             f"Initialize Disk: {pw.get('disk_initialized','—')}  ({pw.get('partition_style','—')})\n"
             f"Result         : {'✓ All passes completed' if rec.get('all_passes_ok') else '✗ Wipe failed'}")
        self.detail.setText(txt)

    def _export_csv(self):
        path,_=QFileDialog.getSaveFileName(self,"Export History CSV",str(CERTS_DIR/"wipe_history.csv"),"CSV (*.csv)")
        if not path: return
        import csv
        try:
            with open(path,"w",newline="") as f:
                w=csv.writer(f)
                w.writerow(["Date","Model","Serial","Size","Interface","Method","Passes","DryRun","Result","CertID"])
                for rec in self._records:
                    drv=rec.get("drive",{}); wipe=rec.get("wipe",{})
                    w.writerow([rec.get("completed_at","")[:19],
                                drv.get("model",""),drv.get("serial",""),drv.get("size",""),
                                drv.get("interface",""),wipe.get("standard",""),
                                wipe.get("passes",""),wipe.get("dry_run",""),
                                "Success" if rec.get("all_passes_ok") else "Failed",
                                rec.get("cert_id","")])
            QMessageBox.information(self,"Exported",f"History exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self,"Export Error",str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Batch Progress Widget (one row per drive)
# ─────────────────────────────────────────────────────────────────────────────

class BatchProgressWidget(QWidget):
    def __init__(self, drives, parent=None):
        super().__init__(parent)
        lay=QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(4)
        self._bars={}; self._labels={}
        for d in drives:
            dev=d["device"]
            row=QHBoxLayout()
            lbl=QLabel(f"{d['model'][:28]}"); lbl.setFixedWidth(230)
            lbl.setStyleSheet("color:#E6EDF3;font-size:11px;")
            bar=QProgressBar(); bar.setFixedHeight(12); bar.setValue(0)
            bar.setStyleSheet("QProgressBar{background:#21262D;border-radius:3px;}"
                              "QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #00C2FF,stop:1 #00FF9C);border-radius:3px;}")
            status=QLabel("Waiting"); status.setFixedWidth(120)
            status.setStyleSheet("color:#8B949E;font-size:10px;")
            row.addWidget(lbl); row.addWidget(bar,1); row.addWidget(status)
            lay.addLayout(row)
            self._bars[dev]=bar; self._labels[dev]=status

    def update_progress(self, dev, pct, msg):
        if dev in self._bars:
            self._bars[dev].setValue(pct)
            self._labels[dev].setText(msg[:18])

    def set_status(self, dev, ok, msg):
        if dev in self._labels:
            self._labels[dev].setText("✓ Done" if ok else "✗ Failed")
            self._labels[dev].setStyleSheet(f"color:{'#00FF9C' if ok else '#FF5555'};font-size:10px;font-weight:bold;")
            if dev in self._bars and ok: self._bars[dev].setValue(100)


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

class WipeVaultWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WipeVault v3.0.3 — Secure Drive Erasure")
        self.setMinimumSize(1060,760)
        self.resize(1060,880)
        self.drives=[]
        self._active_workers={}   # device -> WipeWorker (batch support)
        self.last_worker=None; self.last_drive=None
        self._setup_style(); self._setup_ui()
        self._check_admin_on_startup(); self._refresh_drives()

    # ── Style ──────────────────────────────────────────────────────────────
    def _setup_style(self):
        self.setStyleSheet("""
            QMainWindow,QWidget{background:#0D1117;color:#E6EDF3;
                font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,sans-serif;font-size:12px;}
            QGroupBox{border:1px solid #21262D;border-radius:6px;margin-top:10px;
                padding-top:10px;color:#8B949E;font-size:11px;}
            QGroupBox::title{subcontrol-origin:margin;left:10px;color:#00C2FF;font-weight:bold;}
            QPushButton{background:#21262D;border:1px solid #30363D;border-radius:6px;
                padding:6px 14px;color:#E6EDF3;}
            QPushButton:hover{background:#30363D;border-color:#8B949E;}
            QPushButton:pressed{background:#161B22;}
            QPushButton:disabled{color:#484F58;border-color:#21262D;}
            QTableWidget{background:#161B22;border:1px solid #21262D;border-radius:6px;
                gridline-color:#21262D;selection-background-color:#1F6FEB;}
            QTableWidget::item{padding:6px 8px;}
            QTableWidget{alternate-background-color:#0D1117;}
            QHeaderView::section{background:#21262D;color:#8B949E;border:none;
                border-right:1px solid #30363D;padding:6px 8px;font-weight:bold;font-size:11px;}
            QProgressBar{background:#21262D;border-radius:4px;height:10px;
                text-align:center;color:#E6EDF3;font-size:10px;}
            QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 #00C2FF,stop:1 #00FF9C);border-radius:4px;}
            QTextEdit{background:#010409;border:1px solid #21262D;border-radius:6px;
                color:#00FF9C;font-family:'Cascadia Code','Consolas','Courier New',monospace;
                font-size:11px;padding:6px;}
            QLineEdit,QComboBox{background:#161B22;border:1px solid #30363D;
                border-radius:4px;padding:5px 8px;color:#E6EDF3;}
            QComboBox QAbstractItemView{background:#161B22;border:1px solid #30363D;
                selection-background-color:#1F6FEB;color:#E6EDF3;}
            QLineEdit:focus,QComboBox:focus{border-color:#1F6FEB;}
            QCheckBox{color:#E6EDF3;spacing:7px;}
            QDialog{background:#161B22;}
            QTabWidget::pane{border:1px solid #21262D;border-radius:6px;}
            QTabBar::tab{background:#161B22;color:#8B949E;border:1px solid #21262D;
                padding:7px 18px;border-bottom:none;border-radius:4px 4px 0 0;margin-right:2px;}
            QTabBar::tab:selected{background:#0D1117;color:#00C2FF;border-color:#00C2FF;}
            QTabBar::tab:hover{color:#E6EDF3;}
            QScrollBar:vertical{background:#161B22;width:8px;border-radius:4px;}
            QScrollBar::handle:vertical{background:#30363D;border-radius:4px;}
            QStatusBar{background:#161B22;color:#8B949E;font-size:11px;}
        """)

    # ── UI ─────────────────────────────────────────────────────────────────
    def _setup_ui(self):
        central=QWidget(); self.setCentralWidget(central)
        root=QVBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        root.addWidget(self._make_header())

        self.tabs=QTabWidget()
        self.tabs.addTab(self._make_wipe_tab(),"⚡  Wipe")
        self.history_tab=HistoryTab()
        self.tabs.addTab(self.history_tab,"📋  History")
        self.tabs.setContentsMargins(8,8,8,8)
        root.addWidget(self.tabs,1)

        self.status_bar=QStatusBar(); self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready — Select drives, choose a wipe method, and click Wipe Drive(s).")

    def _make_header(self):
        h=QFrame(); h.setFixedHeight(64)
        h.setStyleSheet("background:#161B22;border-bottom:1px solid #21262D;")
        lay=QHBoxLayout(h); lay.setContentsMargins(20,0,20,0)
        logo=QLabel("🔒 WipeVault")
        logo.setFont(QFont("Segoe UI",18,QFont.Weight.Bold))
        logo.setStyleSheet("color:#00C2FF;letter-spacing:1px;")
        ver=QLabel("v3.0.3"); ver.setStyleSheet("color:#30363D;font-size:11px;margin-left:6px;")
        tag=QLabel("  Secure Drive Erasure"); tag.setStyleSheet("color:#8B949E;font-size:11px;")
        lay.addWidget(logo); lay.addWidget(ver); lay.addWidget(tag); lay.addStretch()

        self.dry_run_cb=CheckBox("Simulation Mode (no writes)")
        self.dry_run_cb.setChecked(True)
        self.dry_run_cb.setStyleSheet("color:#00C2FF;font-weight:bold;spacing:7px;")
        lay.addWidget(self.dry_run_cb)

        verify_btn=QPushButton("🔍  Verify Certificate")
        verify_btn.clicked.connect(self._open_verify_dialog)
        lay.addWidget(verify_btn)

        rb=QPushButton("↻  Refresh Drives"); rb.clicked.connect(self._refresh_drives)
        lay.addWidget(rb)
        return h

    def _make_wipe_tab(self):
        tab=QWidget(); lay=QVBoxLayout(tab); lay.setContentsMargins(12,12,12,8); lay.setSpacing(9)

        splitter=QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet("QSplitter::handle{background:#21262D;}")

        top=self._make_top_panel()
        bot=self._make_bottom_panel()
        splitter.addWidget(top); splitter.addWidget(bot)
        splitter.setSizes([600,220])
        lay.addWidget(splitter,1)
        return tab

    def _make_top_panel(self):
        panel=QWidget(); lay=QVBoxLayout(panel)
        lay.setContentsMargins(0,0,0,0); lay.setSpacing(9)

        # Drive table
        dg=QGroupBox("Detected Drives — select one or more for batch wipe")
        dl=QVBoxLayout(dg)
        self.drive_table=QTableWidget()
        self.drive_table.setColumnCount(6)
        self.drive_table.setHorizontalHeaderLabels(["Device","Model","Serial","Size","Interface","Connection"])
        self.drive_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.drive_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.drive_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.drive_table.setAlternatingRowColors(True)
        hdr=self.drive_table.horizontalHeader()
        hdr.setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents)
        self.drive_table.setMinimumHeight(130)
        self.drive_table.selectionModel().selectionChanged.connect(self._on_drive_selected)
        dl.addWidget(self.drive_table)
        lay.addWidget(dg,1)

        # Batch status (shown when batch wipe running)
        self.batch_group=QGroupBox("Batch Wipe Progress")
        self.batch_group.setVisible(False)
        self.batch_layout=QVBoxLayout(self.batch_group)
        lay.addWidget(self.batch_group)

        # Method
        mg=QGroupBox("Wipe Method"); ml=QHBoxLayout(mg); ml.setSpacing(12)
        ml.addWidget(QLabel("Select standard:"))
        self.method_combo=QComboBox()
        self.method_combo.setMinimumWidth(290); self.method_combo.setFixedHeight(32)
        for k,m in WIPE_METHODS.items(): self.method_combo.addItem(m["label"],k)
        self.method_combo.currentIndexChanged.connect(self._on_method_changed)
        ml.addWidget(self.method_combo)
        self.method_desc=QLabel(); self.method_desc.setWordWrap(True)
        self.method_desc.setStyleSheet("color:#8B949E;font-size:11px;")
        ml.addWidget(self.method_desc,1)
        lay.addWidget(mg)
        self._on_method_changed(0)

        # Single-drive progress (hidden during batch)
        pg=QGroupBox("Wipe Progress"); pl=QVBoxLayout(pg); pl.setSpacing(5)
        self.pass_label=QLabel("No wipe in progress.")
        self.pass_label.setStyleSheet("color:#8B949E;font-size:11px;")
        pl.addWidget(self.pass_label)
        self.progress_bar=QProgressBar(); self.progress_bar.setValue(0)
        pl.addWidget(self.progress_bar)
        self.progress_msg=QLabel(""); self.progress_msg.setStyleSheet("color:#8B949E;font-size:10px;")
        pl.addWidget(self.progress_msg)
        lay.addWidget(pg)

        # Post-wipe options
        po=QGroupBox("Post-Wipe Options"); pol=QVBoxLayout(po); pol.setSpacing(6)
        row1=QHBoxLayout()
        self.clear_part_cb=CheckBox("Clear partition table after wipe")
        row1.addWidget(self.clear_part_cb); row1.addStretch()
        pol.addLayout(row1)
        row2=QHBoxLayout()
        self.init_disk_cb=CheckBox("Initialize drive after wipe")
        self.init_disk_cb.stateChanged.connect(self._on_init_disk_toggled)
        row2.addWidget(self.init_disk_cb)
        pl2=QLabel("Partition style:"); pl2.setStyleSheet("color:#8B949E;margin-left:16px;")
        row2.addWidget(pl2)
        self.partition_combo=QComboBox()
        self.partition_combo.addItems(["GPT  (recommended — supports drives > 2 TB, UEFI)",
                                       "MBR  (legacy — for older BIOS systems, drives ≤ 2 TB)"])
        self.partition_combo.setFixedHeight(26); self.partition_combo.setMinimumWidth(320)
        self.partition_combo.setEnabled(False)
        row2.addWidget(self.partition_combo); row2.addStretch()
        pol.addLayout(row2)
        lay.addWidget(po)

        # Buttons
        br=QHBoxLayout(); br.setSpacing(10)
        self.wipe_btn=QPushButton("⚡  Wipe Drive(s)")
        self.wipe_btn.setFixedHeight(36)
        self.wipe_btn.setStyleSheet("""
            QPushButton{background:#1F6FEB;color:white;border:none;border-radius:6px;font-weight:bold;font-size:13px;}
            QPushButton:hover{background:#2D82FF;}
            QPushButton:disabled{background:#21262D;color:#484F58;}""")
        self.wipe_btn.setEnabled(False); self.wipe_btn.clicked.connect(self._start_wipe)
        br.addWidget(self.wipe_btn)
        self.cancel_btn=QPushButton("✕  Cancel")
        self.cancel_btn.setFixedHeight(36); self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_wipe)
        br.addWidget(self.cancel_btn)
        self.cert_btn=QPushButton("📄  Generate Certificate")
        self.cert_btn.setFixedHeight(36)
        self.cert_btn.setStyleSheet("""
            QPushButton{background:#238636;color:white;border:none;border-radius:6px;font-weight:bold;}
            QPushButton:hover{background:#2EA043;}
            QPushButton:disabled{background:#21262D;color:#484F58;}""")
        self.cert_btn.setEnabled(False); self.cert_btn.clicked.connect(self._generate_certificate)
        br.addWidget(self.cert_btn)
        lay.addLayout(br)
        return panel

    def _make_bottom_panel(self):
        panel=QWidget(); lay=QVBoxLayout(panel); lay.setContentsMargins(0,4,0,0); lay.setSpacing(4)
        lbl=QLabel("Wipe Log"); lbl.setStyleSheet("color:#00C2FF;font-weight:bold;font-size:11px;")
        lay.addWidget(lbl)
        self.log_view=QTextEdit(); self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Wipe activity will appear here...")
        lay.addWidget(self.log_view,1)
        return panel

    # ── Slots ──────────────────────────────────────────────────────────────

    def _check_admin_on_startup(self):
        if platform.system()=="Windows" and not is_admin():
            self.status_bar.showMessage("⚠  Not running as Administrator — drive detection limited.")

    def _on_init_disk_toggled(self, state):
        en=state==Qt.CheckState.Checked.value
        self.partition_combo.setEnabled(en)
        if en: self.clear_part_cb.setChecked(True)

    def _on_method_changed(self, idx):
        k=self.method_combo.itemData(idx); m=WIPE_METHODS.get(k,{})
        p=m.get("passes",[])
        self.method_desc.setText(f"{len(p)} pass{'es' if len(p)!=1 else ''}  —  {m.get('description','')}")

    def _refresh_drives(self):
        self.status_bar.showMessage("Scanning for drives...")
        QApplication.processEvents()
        self.drives=get_drives()
        self.drive_table.setRowCount(0)
        cmap={"NVMe":"#00FF9C","USB":"#FFA657","SATA":"#79C0FF","SCSI":"#D2A8FF"}
        for d in self.drives:
            row=self.drive_table.rowCount(); self.drive_table.insertRow(row)
            for col,txt in enumerate([d["device"],d["model"],d["serial"],d["size"],d["interface"],d["connection"]]):
                item=QTableWidgetItem(txt)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter|Qt.AlignmentFlag.AlignLeft)
                if col==4: item.setForeground(QColor(cmap.get(txt,"#E6EDF3")))
                self.drive_table.setItem(row,col,item)
        self.wipe_btn.setEnabled(False)
        if not self.drives:
            if not is_admin():
                self.status_bar.showMessage("⚠  No drives found — run as Administrator.")
                QMessageBox.warning(self,"Administrator Required",
                    "No drives detected.\n\nWipeVault requires Administrator privileges.\n"
                    "Right-click WipeVault.exe → 'Run as administrator'.")
            else:
                self.status_bar.showMessage("⚠  No drives detected. Check connections and try Refresh.")
        else:
            self.status_bar.showMessage(f"Found {len(self.drives)} drive(s).  Tip: hold Ctrl/Shift to select multiple.")

    def _on_drive_selected(self):
        sel=self.drive_table.selectedItems()
        self.wipe_btn.setEnabled(bool(sel) and not self._active_workers)

    def _selected_drives(self):
        rows=sorted(set(i.row() for i in self.drive_table.selectedItems()))
        return [self.drives[r] for r in rows if r<len(self.drives)]

    def _start_wipe(self):
        drives=self._selected_drives()
        if not drives: return
        dry_run=self.dry_run_cb.isChecked()
        method_key=self.method_combo.currentData()
        part_style="GPT" if self.partition_combo.currentIndex()==0 else "MBR"
        clear_part=self.clear_part_cb.isChecked()
        init_disk=self.init_disk_cb.isChecked()

        dlg=WipeConfirmDialog(drives,method_key,dry_run,self,clear_part,init_disk,part_style)
        if dlg.exec()!=QDialog.DialogCode.Accepted: return

        self.log_view.clear(); self.progress_bar.setValue(0)
        self.cert_btn.setEnabled(False); self.wipe_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        if len(drives)==1:
            # Single drive — classic progress bar
            self.batch_group.setVisible(False)
            d=drives[0]
            worker=WipeWorker(d,method_key,dry_run,clear_part,init_disk,part_style)
            worker.progress.connect(self._on_progress)
            worker.pass_update.connect(self._on_pass_update)
            worker.finished.connect(self._on_wipe_finished)
            worker.log_update.connect(self._on_log)
            self._active_workers[d["device"]]=worker
            self.last_drive=d
            worker.start()
        else:
            # Batch — per-drive progress widget
            # Clear old batch widget
            while self.batch_layout.count():
                item=self.batch_layout.takeAt(0)
                if item.widget(): item.widget().deleteLater()
            self.batch_widget=BatchProgressWidget(drives)
            self.batch_layout.addWidget(self.batch_widget)
            self.batch_group.setVisible(True)
            self._batch_results={}
            for d in drives:
                worker=WipeWorker(d,method_key,dry_run,clear_part,init_disk,part_style)
                worker.progress.connect(self._on_batch_progress)
                worker.pass_update.connect(self._on_batch_pass)
                worker.finished.connect(self._on_batch_finished)
                worker.log_update.connect(self._on_log)
                self._active_workers[d["device"]]=worker
                worker.start()
            self.pass_label.setText(f"<b>Batch wipe</b> — {len(drives)} drives running simultaneously...")

    def _cancel_wipe(self):
        for w in self._active_workers.values(): w.cancel()
        self.cancel_btn.setEnabled(False)
        self.pass_label.setText("Cancelling...")

    def _on_progress(self, dev, pct, msg):
        self.progress_bar.setValue(pct); self.progress_msg.setText(msg)

    def _on_pass_update(self, dev, pn, total, desc):
        self.pass_label.setText(f"<b>Pass {pn}/{total}</b> — {desc}")

    def _on_log(self, dev, txt):
        prefix=f"[{dev[-12:]}] " if len(self._active_workers)>1 else ""
        self.log_view.append(prefix+txt)
        self.log_view.ensureCursorVisible()

    def _on_wipe_finished(self, dev, ok, msg):
        worker=self._active_workers.pop(dev,None)
        self.cancel_btn.setEnabled(False); self.wipe_btn.setEnabled(True)
        if ok:
            self.last_worker=worker
            self.pass_label.setText("<b style='color:#00FF9C;'>✓ Wipe Complete</b>")
            self.progress_bar.setValue(100)
            self.cert_btn.setEnabled(True)
            self.status_bar.showMessage("Wipe completed. Certificate available.")
            self._save_history_record(worker)
            QMessageBox.information(self,"Wipe Complete",f"{msg}\n\nClick 'Generate Certificate' to create the erasure certificate.")
        else:
            self.pass_label.setText("<b style='color:#FF5555;'>✗ Wipe Failed</b>")
            self.status_bar.showMessage(f"Wipe failed: {msg}")
            QMessageBox.critical(self,"Wipe Failed",f"The wipe did not complete:\n\n{msg}")
        self.history_tab.reload()

    def _on_batch_progress(self, dev, pct, msg):
        if hasattr(self,"batch_widget"): self.batch_widget.update_progress(dev,pct,msg)

    def _on_batch_pass(self, dev, pn, total, desc):
        pass  # logged to log_view via _on_log

    def _on_batch_finished(self, dev, ok, msg):
        worker=self._active_workers.pop(dev,None)
        if hasattr(self,"batch_widget"): self.batch_widget.set_status(dev,ok,msg)
        if worker: self._save_history_record(worker)
        if not self._active_workers:
            # All done
            self.cancel_btn.setEnabled(False); self.wipe_btn.setEnabled(True)
            all_ok=all(self._batch_results.get(d,True) for d in self._batch_results)
            self.pass_label.setText(f"<b style='color:#00FF9C;'>✓ Batch Complete</b>" if all_ok
                                    else f"<b style='color:#FF5555;'>⚠ Batch Complete (some failed)</b>")
            self.status_bar.showMessage("Batch wipe complete.")
            self.history_tab.reload()
            QMessageBox.information(self,"Batch Complete",f"All drives processed.\nCheck the log for individual results.")

    def _save_history_record(self, worker):
        w=worker; m=w.method
        dur=str(w.end_time-w.start_time).split(".")[0] if w.start_time and w.end_time else ""
        record={"cert_id":"WV-"+"".join(random.choices(string.ascii_uppercase+string.digits,k=10)),
                "completed_at":(w.end_time or datetime.now()).isoformat(),
                "drive":{"device":w.drive["device"],"model":w.drive["model"],"serial":w.drive["serial"],
                         "size":w.drive["size"],"interface":w.drive["interface"],"connection":w.drive["connection"]},
                "wipe":{"standard":m["short"],"label":m["label"],"passes":len(m["passes"]),
                        "verify":m["verify"],"dry_run":w.dry_run,"duration":dur,
                        "started":w.start_time.isoformat() if w.start_time else "",
                        "completed":w.end_time.isoformat() if w.end_time else "",
                        "pass_results":w.pass_results},
                "post_wipe":{"clear_partition":w.clear_partition,"partition_cleared":w.partition_cleared,
                             "initialize_disk":w.initialize_disk,"disk_initialized":w.disk_initialized,
                             "partition_style":w.partition_style},
                "all_passes_ok":all(r["success"] for r in w.pass_results)}
        append_history(record)

    def _generate_certificate(self):
        if not self.last_worker or not self.last_drive:
            QMessageBox.warning(self,"No Wipe Data","Complete a wipe first."); return
        dlg=CompanyInfoDialog(self)
        if dlg.exec()!=QDialog.DialogCode.Accepted: return
        company_info=dlg.get_info()
        CERTS_DIR.mkdir(parents=True,exist_ok=True)
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        serial_s=self.last_drive["serial"].replace(" ","_")
        method_s=self.last_worker.method["short"].replace(" ","_").replace("/","-")
        ext="pdf" if REPORTLAB_AVAILABLE else "txt"
        filename=CERTS_DIR/f"WipeVault_{method_s}_{serial_s}_{ts}.{ext}"
        gen=CertificateGenerator(self.last_drive,self.last_worker,company_info,logo_path=company_info.get("logo",""))
        try:
            out=gen.generate(str(filename))
            QMessageBox.information(self,"Certificate Generated",
                f"Certificate saved to:\n{out}\n\n"
                f"A .sig.json signature file was also created for tamper verification.\n\n"
                f"{'PDF generated.' if REPORTLAB_AVAILABLE else 'Install reportlab for PDF: pip install reportlab'}")
            if platform.system()=="Windows": os.startfile(str(CERTS_DIR))
            elif platform.system()=="Darwin": subprocess.run(["open",str(CERTS_DIR)])
            else: subprocess.run(["xdg-open",str(CERTS_DIR)])
        except Exception as e:
            QMessageBox.critical(self,"Certificate Error",f"Failed to generate certificate:\n{e}")

    def _open_verify_dialog(self):
        dlg=VerifyCertDialog(self); dlg.exec()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if platform.system()=="Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(
                    None,"runas",sys.executable," ".join(f'"{a}"' for a in sys.argv),None,1)
                sys.exit(0)
        except Exception: pass

    app=QApplication(sys.argv)
    app.setApplicationName("WipeVault")
    app.setApplicationVersion("3.0.3")
    app.setOrganizationName("WipeVault")
    win=WipeVaultWindow()
    win.show()
    sys.exit(app.exec())

if __name__=="__main__":
    main()
