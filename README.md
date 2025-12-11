# ![A-NIDS Logo](https://github.com/alterteknet/a-nids/blob/main/logo.png)

# 🧠 Adaptive NIDS v1 (A-NIDS v.alpha-1)

**Adaptive NIDS (A-NIDS)** is an enhanced module for **Stratosphere Linux IPS (SLIPS)** that integrates **XGBoost-based machine learning** and **signature-based detection** to improve anomaly detection, precision, and adaptability in virtualized or distributed network environments.

This implementation is **optimized for VMware infrastructures** with **Virtual Distributed Switch (VDS)** and **port mirroring** to capture intra-VM traffic.  
It also includes **Filebeat integration** to forward detection logs from SLIPS to a **SIEM platform** such as **Wazuh, ELK, or Splunk** for centralized monitoring and analytics.

---

## ⚙️ Prerequisites

Ensure the following requirements before installation:

| Component | Requirement |
|------------|-------------|
| **Operating System** | Ubuntu 22.04 LTS (minimum) |
| **CPU** | 4 vCPU |
| **Memory** | 16 GB RAM |
| **Disk Space** | 58 GB minimum |
| **Network Interfaces** | 2 NICs — one for management, one for sniffing/port mirroring |
| **Required Software** | [Stratosphere Linux IPS (SLIPS)](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html) |
| **Wireshark** | Installed and configured for non-root capture |
| **Filebeat** | Installed and configured to forward alert logs to a SIEM server |

---

### 🧾 Enable Wireshark for Non-Root Capture

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
sudo reboot
```

---

### 🧾 Install & Configure Filebeat (for SIEM Integration)

Filebeat forwards log data from SLIPS to your central SIEM server.

```bash
sudo apt install filebeat -y
sudo nano /etc/filebeat/filebeat.yaml
```

**Example Configuration:**
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /path/to/StratosphereLinuxIPS/output/alert.log
    fields:
      source: "AdaptiveNIDS"
      module: "flowmldetection"
      format: "slips"
    fields_under_root: true

output.logstash:
  hosts: ["<SIEM_SERVER_IP>:5045"]
```

> 🟢 **Note:** Replace `<SIEM_SERVER_IP>` with your SIEM server IP address.  
> Default port `5045` is used for Wazuh / ELK Logstash listener (adjust if needed).

Activate Filebeat:
```bash
sudo systemctl enable filebeat
sudo systemctl restart filebeat
```

✅ Filebeat will now forward all SLIPS and A-NIDS alerts to your SIEM in real time.

---

## 🧩 Installation Steps

### 1️⃣ Install Stratosphere Linux IPS (SLIPS)

Follow the official guide:  
🔗 [https://stratospherelinuxips.readthedocs.io/en/develop/installation.html](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html)

```bash
sudo apt update
sudo apt install python3-pip git
git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
cd StratosphereLinuxIPS
sudo ./install.sh
```

---

### 2️⃣ Copy the A-NIDS Main Script

```bash
cp anids-v1.py /path/to/StratosphereLinuxIPS/
```

---

### 3️⃣ Copy Supporting Files

```bash
cp blacklist_ips.txt features_xgboost.json flowdb.sqlite model_xgboost.bin scaler_xgboost.bin /path/to/StratosphereLinuxIPS/modules/flowmldetection/
```

---

### 4️⃣ Set Execution Permission

```bash
chmod 775 /path/to/StratosphereLinuxIPS/anids-v1.py
```

---

## 🚀 Usage

A-NIDS supports multiple modes: **training**, **live detection**, **testing**, and **database viewing**.

---

### 🔹 Display Help Menu

```bash
python3 anids-v1.py -h
```

Output:
```
usage: anids-v1.py [-h] [-f FILE] -i INTERFACE [--test] [--view-db]

Hybrid Flow ML Detection (XGBoost + Signature)
```

---

### 🔹 Live Detection Mode (Hybrid ML + Signature)

Run the hybrid detection engine on the sniffing interface:
```bash
sudo python3 anids-v1.py -i eth1
```

Detected flows will be printed in the console and logged to:
- `/StratosphereLinuxIPS/modules/flowmldetection/flowdb.sqlite`
- `/StratosphereLinuxIPS/output/alert.log`

Example log:
```
[Flow ML Detection] INFO: 192.168.1.10:54321 -> 10.10.10.5:80 proto=TCP prob=0.991 label=Malware reason=SYN-DDoS
```

---

### 🔹 Train a New Model from CSV

```bash
python3 anids-v1.py -f dataset_ddos.csv
```

This updates:
- `model_xgboost.bin`
- `scaler_xgboost.bin`

---

### 🔹 Test Model Performance

```bash
python3 anids-v1.py --test
```

Displays:
- Accuracy  
- Precision, Recall, and F1-Score  
- Confusion Matrix  
- Training and Testing Time  

---

### 🔹 View Detection Database

```bash
python3 anids-v1.py --view-db
```

Displays all recorded detections from the SQLite database.

---

### 🔹 Common Usage Examples

| Scenario | Example Command |
|-----------|----------------|
| Run live detection on sniffer interface | `sudo python3 anids-v1.py -i ens224` |
| Train using CICDDoS dataset | `python3 anids-v1.py -f cicddos_day3_11.csv` |
| View local database results | `python3 anids-v1.py --view-db` |
Flow Documentation [Pseudo Code](https://www.dropbox.com/scl/fi/jrs8y0a68ii2opq8c8712/Pseudo-Code.pdf?rlkey=mcf280x9onymtpxayk7ptj0l2&dl=0)
---

## 📊 Log and Output Paths

| Path | Description |
|------|--------------|
| `/StratosphereLinuxIPS/output/alert.log` | Real-time detection alerts (for Filebeat → SIEM) |
| `/StratosphereLinuxIPS/modules/flowmldetection/flowdb.sqlite` | Local database for captured flows |
| `model_xgboost.bin` | Trained XGBoost model |
| `scaler_xgboost.bin` | Feature normalization object |
| `features_xgboost.json` | Feature configuration definition |

---

## 📂 File Overview

| File | Description |
|------|--------------|
| `anids-v1.py` | Main Adaptive NIDS Python script |
| `blacklist_ips.txt` | List of known malicious IP addresses |
| `features_xgboost.json` | Feature configuration for XGBoost |
| `flowdb.sqlite` | Local database for captured flow records |
| `model_xgboost.bin` | Pre-trained XGBoost ML model |
| `scaler_xgboost.bin` | Scaler object for normalization |
| `README.md` | Documentation file |

---

## 🧠 Author

**Alter Gajahmada**  
🔗 [www.altertek.net](https://www.altertek.net)
Inspired by [Stratosphere Linux IPS](https://stratosphereips.org)
