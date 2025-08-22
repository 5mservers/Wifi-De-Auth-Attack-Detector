from __future__ import annotations

import os
import sys
import time
import socket
import threading
import logging
import logging.handlers
from dataclasses import dataclass, field
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple, List


from PySide6 import QtCore, QtGui, QtWidgets


try:
    from scapy.all import sniff, conf, get_if_list, arping
    from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap
    SCAPY_OK = True
except Exception as e:  
    SCAPY_OK = False
    SCAPY_IMPORT_ERROR = e

try:
    import psutil
except Exception as e:  
    raise SystemExit("psutil is required. Install with: pip install psutil")

try:
    from mac_vendor_lookup import MacLookup
    MAC_LOOKUP = MacLookup()
except Exception:
    MAC_LOOKUP = None

from ipaddress import ip_interface, IPv4Network

APP_NAME = "Wi‑Fi Guardian"
LOG_DIR = os.path.join(os.path.expanduser("~"), ".wifi_guardian")
LOG_PATH = os.path.join(LOG_DIR, "guardian.log")


class RotatingFileHandlerSafe(logging.handlers.RotatingFileHandler):
    pass


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

LOGGER = setup_logging()


@dataclass
class DeauthAlert:
    ts: float
    bssid: str
    src: str
    dst: str
    reason: int
    count_in_window: int
    rssi: Optional[int] = None
    channel_mhz: Optional[int] = None
    kind: str = "DEAUTH" 

    @property
    def severity(self) -> str:
        if self.count_in_window >= 50:
            return "critical"
        if self.count_in_window >= 20:
            return "high"
        return "medium"


REASON_MAP = {
    1: "Unspecified",
    2: "Auth expired",
    3: "Deauth from AP (leaving)",
    4: "Inactivity",
    5: "AP cannot handle all stations",
    6: "Class 2 frame from non‑auth station",
    7: "Class 3 frame from non‑assoc station",
    8: "Leaving BSS",
    9: "Association too many stations",
    10: "Disassoc from AP (leaving)",
}



def safe_mac(mac: Optional[str]) -> str:
    if not mac:
        return "?"
    return mac.upper()


def vendor_for_mac(mac: str) -> str:
    if MAC_LOOKUP is None:
        return "—"
    try:
        return MAC_LOOKUP.lookup(mac)
    except Exception:
        return "—"


def get_active_ipv4() -> Tuple[str, str, str]:
    """Return (ip, netmask, ifname) for the interface used to reach the internet."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            for ifname, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        return a.address, a.netmask, ifname
            raise
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and a.address == ip:
                return ip, a.netmask, ifname
    raise RuntimeError("Active IPv4 interface not found")



class DeauthDetector(QtCore.QObject):
    alert_emitted = QtCore.Signal(DeauthAlert)
    heartbeat = QtCore.Signal(int)  

    def __init__(self, window_seconds: int = 10, threshold: int = 20):
        super().__init__()
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._by_bssid: Dict[str, Deque[float]] = defaultdict(deque)
        self._count = 0
        self._running = False
        self._lock = threading.Lock()

    def reset(self):
        with self._lock:
            self._by_bssid.clear()
            self._count = 0

    def process(self, pkt) -> None:
        now = time.monotonic()
        self._count += 1
        if self._count % 200 == 0:
            self.heartbeat.emit(self._count)

        if not pkt.haslayer(Dot11):
            return
        dot11 = pkt[Dot11]
        bssid = safe_mac(getattr(dot11, "addr3", None))
        src = safe_mac(getattr(dot11, "addr2", None))
        dst = safe_mac(getattr(dot11, "addr1", None))

        kind = None
        reason = None
        if pkt.haslayer(Dot11Deauth):
            kind = "DEAUTH"
            reason = int(getattr(pkt[Dot11Deauth], "reason", 0))
        elif pkt.haslayer(Dot11Disas):
            kind = "DISASSOC"
            reason = int(getattr(pkt[Dot11Disas], "reason", 0))
        else:
            return


        dq = self._by_bssid[bssid]
        dq.append(now)
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)
        rssi = None
        chan = None
        try:
            if pkt.haslayer(RadioTap):
                rt = pkt[RadioTap]
                rssi = getattr(rt, "dBm_AntSignal", None)
                chan = getattr(rt, "ChannelFrequency", None)
        except Exception:
            pass

        if count >= self.threshold:
            alert = DeauthAlert(
                ts=time.time(),
                bssid=bssid,
                src=src,
                dst=dst,
                reason=reason or 0,
                count_in_window=count,
                rssi=rssi,
                channel_mhz=chan,
                kind=kind,
            )
            self.alert_emitted.emit(alert)


class SnifferThread(QtCore.QThread):
    pkt_signal = QtCore.Signal(object)

    def __init__(self, iface: str):
        super().__init__()
        self.iface = iface
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        if not SCAPY_OK:
            self.pkt_signal.emit(("ERROR", f"Scapy not available: {SCAPY_IMPORT_ERROR}"))
            return
        try:
            conf.sniff_promisc = True
            sniff(
                iface=self.iface,
                prn=lambda p: (not self._stop_event.is_set()) and self.pkt_signal.emit(p),
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except Exception as e:
            self.pkt_signal.emit(("ERROR", f"Sniffer error on {self.iface}: {e}"))



@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "—"
    hostname: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class DeviceScanner(QtCore.QObject):
    devices_updated = QtCore.Signal(dict)
    status = QtCore.Signal(str)

    def __init__(self, interval_sec: int = 30):
        super().__init__()
        self.interval_sec = interval_sec
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._scan_once)
        self._net: Optional[IPv4Network] = None
        self._iface: Optional[str] = None
        self._devices: Dict[str, Device] = {}

    def start(self):
        try:
            ip, mask, ifname = get_active_ipv4()
            iface = next(
                (name for name, addrs in psutil.net_if_addrs().items() for a in addrs if a.family == socket.AF_INET and a.address == ip),
                None,
            )
            self._iface = iface or ifname
            cidr = ip_interface(f"{ip}/{mask}").network
            self._net = cidr
            self.status.emit(f"LAN: {cidr} via {self._iface}")
        except Exception as e:
            self.status.emit(f"LAN detection failed: {e}")
        self._timer.start(self.interval_sec * 1000)
        QtCore.QTimer.singleShot(1000, self._scan_once)

    def stop(self):
        self._timer.stop()

    def _scan_once(self):
        if self._net is None or not SCAPY_OK:
            return
        try:
            ans, _ = arping(str(self._net), timeout=2, verbose=0)
            now = time.time()
            for s, r in ans:
                ip = r.psrc
                mac = r.hwsrc.upper()
                if mac not in self._devices:
                    hostname = ""
                    try:
                        hostname = socket.getfqdn(ip)
                        if hostname == ip:
                            hostname = ""
                    except Exception:
                        hostname = ""
                    self._devices[mac] = Device(
                        ip=ip,
                        mac=mac,
                        vendor=vendor_for_mac(mac),
                        hostname=hostname,
                    )
                self._devices[mac].ip = ip
                self._devices[mac].last_seen = now
            cutoff = time.time() - (self.interval_sec * 5)
            self._devices = {m: d for m, d in self._devices.items() if d.last_seen >= cutoff}
            self.devices_updated.emit(self._devices)
            self.status.emit(f"Devices active: {len(self._devices)}")
        except Exception as e:
            self.status.emit(f"ARP scan error: {e}")


class Badge(QtWidgets.QLabel):
    def __init__(self, text: str, kind: str = "info", parent=None):
        super().__init__(text, parent)
        self.setAlignment(QtCore.Qt.AlignCenter)
        self.setStyleSheet({
            "info": "background:#2d3748;color:#e2e8f0;border-radius:8px;padding:4px 8px;",
            "ok": "background:#065f46;color:#d1fae5;border-radius:8px;padding:4px 8px;",
            "warn": "background:#92400e;color:#fef3c7;border-radius:8px;padding:4px 8px;",
            "err": "background:#7f1d1d;color:#fee2e2;border-radius:8px;padding:4px 8px;",
        }["info"]) 
        self.set_kind(kind)

    def set_kind(self, kind: str):
        styles = {
            "info": "background:#2d3748;color:#e2e8f0;border-radius:8px;padding:4px 8px;",
            "ok": "background:#065f46;color:#d1fae5;border-radius:8px;padding:4px 8px;",
            "warn": "background:#92400e;color:#fef3c7;border-radius:8px;padding:4px 8px;",
            "err": "background:#7f1d1d;color:#fee2e2;border-radius:8px;padding:4px 8px;",
        }
        self.setStyleSheet(styles.get(kind, styles["info"]))


class LogView(QtWidgets.QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setMaximumBlockCount(1000)
        self.setStyleSheet("background:#0f172a;color:#e2e8f0;border-radius:12px;padding:8px;")
        self.setFont(QtGui.QFont("JetBrains Mono, Consolas, monospace", 10))

    def append_line(self, text: str):
        self.appendPlainText(text)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


class AlertsTable(QtWidgets.QTableWidget):
    HEADERS = ["Time", "Type", "BSSID", "SRC", "DST", "Reason", "Count", "RSSI", "Channel"]

    def __init__(self):
        super().__init__(0, len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setStyleSheet("QTableWidget{background:#0b1220;color:#e2e8f0;border-radius:12px;}"
                          "QHeaderView::section{background:#1f2937;color:#cbd5e1;border:0;padding:8px;}")
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)

    def add_alert(self, a: DeauthAlert):
        row = self.rowCount()
        self.insertRow(row)
        ts = time.strftime("%H:%M:%S", time.localtime(a.ts))
        reason_txt = f"{a.reason} ({REASON_MAP.get(a.reason, 'Reason')})"
        values = [
            ts,
            a.kind,
            a.bssid,
            a.src,
            a.dst,
            reason_txt,
            str(a.count_in_window),
            str(a.rssi) if a.rssi is not None else "—",
            str(a.channel_mhz) if a.channel_mhz else "—",
        ]
        for col, val in enumerate(values):
            item = QtWidgets.QTableWidgetItem(val)
            if col == 1:  
                color = QtGui.QColor("#fecaca") if a.kind == "DEAUTH" else QtGui.QColor("#fde68a")
                item.setForeground(QtGui.QBrush(color))
            if col == 6:  
                if a.count_in_window >= 50:
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#fca5a5")))
                elif a.count_in_window >= 20:
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#fde68a")))
            self.setItem(row, col, item)
        self.scrollToBottom()


class DevicesTable(QtWidgets.QTableWidget):
    HEADERS = ["IP", "MAC", "Vendor", "Hostname", "First Seen", "Last Seen"]

    def __init__(self):
        super().__init__(0, len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setStyleSheet("QTableWidget{background:#0b1220;color:#e2e8f0;border-radius:12px;}"
                          "QHeaderView::section{background:#1f2937;color:#cbd5e1;border:0;padding:8px;}")
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)

    def update_devices(self, devices: Dict[str, Device]):
        self.setRowCount(0)
        for dev in devices.values():
            row = self.rowCount()
            self.insertRow(row)
            vals = [
                dev.ip,
                dev.mac,
                dev.vendor,
                dev.hostname or "",
                time.strftime("%H:%M:%S", time.localtime(dev.first_seen)),
                time.strftime("%H:%M:%S", time.localtime(dev.last_seen)),
            ]
        
            for col, v in enumerate(vals):
                self.setItem(row, col, QtWidgets.QTableWidgetItem(v))
        self.resizeColumnsToContents()


class ControlsBar(QtWidgets.QWidget):
    start_clicked = QtCore.Signal()
    stop_clicked = QtCore.Signal()

    def __init__(self, interfaces: List[str]):
        super().__init__()
        layout = QtWidgets.QGridLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(12)

        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.addItems(interfaces)
        self.iface_combo.setEditable(True)
        self.iface_combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.iface_combo.setMinimumWidth(180)

        self.window_spin = QtWidgets.QSpinBox()
        self.window_spin.setRange(2, 120)
        self.window_spin.setValue(10)
        self.window_spin.setSuffix(" s window")

        self.thresh_spin = QtWidgets.QSpinBox()
        self.thresh_spin.setRange(1, 500)
        self.thresh_spin.setValue(20)
        self.thresh_spin.setSuffix(" pkt threshold")

        self.start_btn = QtWidgets.QPushButton("Start Sniffing")
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)

        for b in (self.start_btn, self.stop_btn):
            b.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
            b.setStyleSheet("QPushButton{background:#334155;color:#e2e8f0;border:0;padding:8px 12px;border-radius:10px;}"
                            "QPushButton:hover{background:#475569}")

        self.badge = Badge("Idle", kind="info")

        layout.addWidget(QtWidgets.QLabel("Interface (monitor):"), 0, 0)
        layout.addWidget(self.iface_combo, 0, 1)
        layout.addWidget(self.badge, 0, 2)
        layout.addWidget(self.start_btn, 0, 3)
        layout.addWidget(self.stop_btn, 0, 4)

        layout.addWidget(QtWidgets.QLabel("Sliding window:"), 1, 0)
        layout.addWidget(self.window_spin, 1, 1)
        layout.addWidget(QtWidgets.QLabel("Alert threshold:"), 1, 2)
        layout.addWidget(self.thresh_spin, 1, 3)

        self.setStyleSheet("QLabel{color:#e2e8f0}")

        self.start_btn.clicked.connect(self.start_clicked.emit)
        self.stop_btn.clicked.connect(self.stop_clicked.emit)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1200, 800)
        self._sniffer: Optional[SnifferThread] = None
        self.detector = DeauthDetector()
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        vbox = QtWidgets.QVBoxLayout(central)
        vbox.setContentsMargins(16, 16, 16, 16)
        vbox.setSpacing(12)

        interfaces = []
        if SCAPY_OK:
            try:
                interfaces = get_if_list()
            except Exception:
                interfaces = []
        if not interfaces:
            interfaces = ["wlan0mon", "wlan0", "mon0"]

        self.controls = ControlsBar(interfaces)
        vbox.addWidget(self.controls)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.alerts = AlertsTable()
        self.devices = DevicesTable()
        self.logs = LogView()

        splitter.addWidget(self.alerts)
        splitter.addWidget(self.devices)
        splitter.addWidget(self.logs)
        splitter.setSizes([350, 250, 200])
        vbox.addWidget(splitter)
        self.status = self.statusBar()
        self.status.setStyleSheet("color:#cbd5e1")
        self.status.showMessage("Ready.")
        self._apply_dark_theme()
        self.controls.start_clicked.connect(self._start)
        self.controls.stop_clicked.connect(self._stop)
        self.detector.alert_emitted.connect(self._on_alert)
        self.detector.heartbeat.connect(self._on_heartbeat)
        self.scanner = DeviceScanner(interval_sec=30)
        self.scanner.devices_updated.connect(self._on_devices)
        self.scanner.status.connect(self._info)
        self.scanner.start()
        self._build_menu()

        if not SCAPY_OK:
            self._error(f"Scapy not ready: {SCAPY_IMPORT_ERROR}")


    def _build_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        export_logs = QtGui.QAction("Export Log File…", self)
        export_logs.triggered.connect(self._export_logs)
        file_menu.addAction(export_logs)

        help_menu = menubar.addMenu("&Help")
        about = QtGui.QAction("About", self)
        about.triggered.connect(self._about)
        help_menu.addAction(about)

    def _apply_dark_theme(self):
        p = self.palette()
        p.setColor(QtGui.QPalette.Window, QtGui.QColor("#0b1220"))
        p.setColor(QtGui.QPalette.Base, QtGui.QColor("#0b1220"))
        p.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor("#0f172a"))
        p.setColor(QtGui.QPalette.Text, QtGui.QColor("#e2e8f0"))
        p.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#e2e8f0"))
        p.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("#e2e8f0"))
        p.setColor(QtGui.QPalette.Highlight, QtGui.QColor("#1d4ed8"))
        self.setPalette(p)

    def _info(self, msg: str):
        LOGGER.info(msg)
        self.logs.append_line(msg)
        self.status.showMessage(msg)

    def _error(self, msg: str):
        LOGGER.error(msg)
        self.logs.append_line(f"ERROR: {msg}")
        self.status.showMessage(msg)

    def _on_heartbeat(self, count: int):
        self.controls.badge.setText(f"Packets: {count}")
        self.controls.badge.set_kind("ok")

    def _on_alert(self, alert: DeauthAlert):
        self.alerts.add_alert(alert)
        vendor = vendor_for_mac(alert.bssid)
        msg = (f"{alert.kind} burst: BSSID {alert.bssid} ({vendor}), count={alert.count_in_window}, "
               f"src={alert.src}, dst={alert.dst}, reason={alert.reason}")
        self._error(msg)
        try:
            QtWidgets.QSystemTrayIcon.showMessage(
                QtWidgets.QSystemTrayIcon(), f"{APP_NAME} Alert", msg,
                QtWidgets.QSystemTrayIcon.Critical, 5000,
            )
        except Exception:
            pass

    def _on_devices(self, devices: Dict[str, Device]):
        self.devices.update_devices(devices)

 
    def _start(self):
        iface = self.controls.iface_combo.currentText().strip()
        if not iface:
            self._error("Please select a monitor‑mode interface.")
            return
        self.detector.window_seconds = int(self.controls.window_spin.value())
        self.detector.threshold = int(self.controls.thresh_spin.value())
        self.detector.reset()

        self.controls.start_btn.setEnabled(False)
        self.controls.stop_btn.setEnabled(True)
        self.controls.badge.setText("Sniffing…")
        self.controls.badge.set_kind("ok")

        self._sniffer = SnifferThread(iface)
        self._sniffer.pkt_signal.connect(self._handle_packet)
        self._sniffer.start()
        self._info(f"Sniffing on {iface} (monitor mode required)")

    def _stop(self):
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer.wait(1500)
            self._sniffer = None
        self.controls.start_btn.setEnabled(True)
        self.controls.stop_btn.setEnabled(False)
        self.controls.badge.setText("Idle")
        self.controls.badge.set_kind("info")
        self._info("Sniffer stopped.")

    def _handle_packet(self, pkt_or_msg):
        if isinstance(pkt_or_msg, tuple) and pkt_or_msg and pkt_or_msg[0] == "ERROR":
            self._error(pkt_or_msg[1])
            self._stop()
            return
        try:
            self.detector.process(pkt_or_msg)
        except Exception as e:
            self._error(f"Packet processing error: {e}")

    def _export_logs(self):
        dest, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save log as…", "wifi_guardian.log", "Log files (*.log)")
        if dest:
            try:
                QtCore.QFile.copy(LOG_PATH, dest)
                self._info(f"Log exported to {dest}")
            except Exception as e:
                self._error(f"Export failed: {e}")

    def _about(self):
        QtWidgets.QMessageBox.information(
            self,
            f"About {APP_NAME}",
            (
                f"{APP_NAME}\n\n"
                "Monitors for Wi‑Fi deauthentication/disassociation bursts and\n"
                "tracks active devices on your LAN. Built with PySide6 + Scapy.\n\n"
                "Tips:\n"
                "• Put your adapter into monitor mode before sniffing.\n"
                "• Tune the threshold/window to match your environment.\n"
                "• Look for repeated DEAUTH bursts across time — a strong sign of attacks.\n"
            ),
        )




def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QtGui.QIcon.fromTheme("network-wireless"))

    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main() 
