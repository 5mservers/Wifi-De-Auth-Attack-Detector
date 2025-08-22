# 🛡️ Wi-Fi Guardian  
**Home WLAN Deauth & Device Monitor**

Tired of wondering if someone’s messing with your Wi-Fi?  
Wi-Fi Guardian gives you eyes on the airwaves. Detect deauth attacks, watch devices on your LAN, and get real-time alerts — all with a sleek, modern GUI.  

---

## ✨ Features
- 🔍 **Detect deauth/disassoc floods** — the classic “kick you off Wi-Fi” attack.  
- 📊 **Sliding-window counters** with adjustable thresholds.  
- 🚨 **Live alerts** with severity colours (medium → high → critical).  
- 👀 **Device inventory** — ARP sweep your LAN for IP, MAC, vendor, hostname.  
- 📝 **Rotating log file** + in-app log viewer.  
- 🎨 **Dark UI with PySide6** — sortable tables, status badges, and clean design.  
- ⚡ **Non-blocking, threaded core** — sniffer never freezes the interface.  

---

## 🚀 Quick Start

### Requirements
- Python **3.9+**  
- Install deps:
  ```bash
  pip install -U PySide6 scapy psutil mac-vendor-lookup
  ```
- (Optional, Linux) [`aircrack-ng`](https://www.aircrack-ng.org/) for one-command monitor mode.

### Run
```bash
python Wifi-Scanner.py
```

### Enable Monitor Mode (Linux)
To capture raw 802.11 management frames you’ll need monitor mode:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
# or: sudo airmon-ng start wlan0
```

Then select the monitor interface in the app (`wlan0mon`, `mon0`, etc.).

---

## 🖥️ Platforms
- **Linux** → best support (full deauth detection).  
- **macOS / Windows** → device inventory works everywhere; raw frame capture depends on drivers/chipset.  

---

## ⚖️ Legal & Ethical
This tool is for **defensive monitoring** of your own networks.  
Don’t go sniffing where you don’t have permission.  

---

## 📸 Screenshots
_Add screenshots of the GUI here once you’ve got some nice captures!_  
