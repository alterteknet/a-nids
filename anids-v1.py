#!/usr/bin/env python3
"""
mlsyncv3_final_autoupdate_iana.py – Adaptive NIDS inspired by Stratosphere Linux IPS
Author : Alter Gajahmada
Website: www.altertek.net
"""

import os, sys, json, pickle, argparse, sqlite3, ipaddress, time, csv, requests
import pandas as pd, numpy as np
from datetime import datetime
from tqdm import tqdm
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from xgboost import XGBClassifier

# ======================================
# CONFIGURATION
# ======================================
BASE_DIR = "/home/alter/StratosphereLinuxIPS"
MODULE_DIR = os.path.join(BASE_DIR, "modules", "flowmldetection")
os.makedirs(MODULE_DIR, exist_ok=True)

FLOW_MODEL_PATH = os.path.join(MODULE_DIR, "model_xgboost.bin")
FLOW_SCALER_PATH = os.path.join(MODULE_DIR, "scaler_xgboost.bin")
FLOW_FEATURES_PATH = os.path.join(MODULE_DIR, "features_xgboost.json")
BLACKLIST_PATH = os.path.join(MODULE_DIR, "blacklist_ips.txt")
DB_PATH = os.path.join(MODULE_DIR, "flowdb.sqlite")

OUTPUT_DIR = os.path.join(BASE_DIR, "output", "test")
os.makedirs(OUTPUT_DIR, exist_ok=True)
ALERT_LOG = os.path.join(OUTPUT_DIR, "alert.log")

MODEL_PROB_THRESHOLD = 0.6
PORT_CACHE = os.path.join(MODULE_DIR, "iana_ports.csv")

# ======================================
# UTILITIES
# ======================================
def banner():
    print("=" * 70)
    print(" Adaptive NIDS inspired by Stratosphere Linux IPS")
    print(" Author : Alter Gajahmada (finalized)")
    print(" Website: www.altertek.net")
    print("=" * 70 + "\n")

def now_ts(): return datetime.now().strftime("%Y/%m/%d %H:%M:%S")
def log_alert(msg): open(ALERT_LOG, "a").write(msg + "\n")

def sanitize_dataframe(X):
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X.clip(lower=-1e9, upper=1e9).astype(np.float64)

def severity_from_prob(p):
    if p >= 0.9: return "HIGH"
    if p >= 0.6: return "MEDIUM"
    if p >= 0.5: return "LOW"
    return "INFO"

def proto_to_num(proto): return {"TCP":6, "UDP":17, "ICMP":1}.get(str(proto).upper(), 0)
def normalize_ip(ip):
    try: return str(ipaddress.ip_address(ip))
    except: return str(ip).strip().lower()

# ======================================
# AUTO-UPDATE IANA PORT SERVICES
# ======================================
LOCAL_PORT_SERVICES = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",123:"NTP",135:"MS-RPC",137:"NetBIOS-NS",
    138:"NetBIOS-DGM",139:"NetBIOS-SSN",143:"IMAP",161:"SNMP",162:"SNMP-TRAP",
    389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",514:"SYSLOG",587:"SMTP-Submission",
    631:"IPP",636:"LDAPS",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5601:"Kibana",5672:"AMQP",
    5900:"VNC",6379:"Redis",8080:"HTTP-Proxy",8443:"HTTPS-Alt",9000:"SonarQube",
    9090:"Web-Admin",9200:"Elasticsearch",9300:"Elastic-Node",11211:"Memcached",
    15672:"RabbitMQ-HTTP",27017:"MongoDB",51820:"WireGuard",
    1514:"Wazuh-Agent",55000:"Wazuh-Manager"
}

def fetch_iana_ports():
    url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            with open(PORT_CACHE, "wb") as f: f.write(r.content)
            print(f"[INFO] Updated IANA port list ({len(r.content)} bytes).")
            return True
    except Exception as e:
        print(f"[WARN] IANA port update failed: {e}")
    return False

def load_port_services():
    need_update = True
    if os.path.exists(PORT_CACHE):
        age_days = (datetime.now() - datetime.fromtimestamp(os.path.getmtime(PORT_CACHE))).days
        if age_days <= 30: need_update = False
    if need_update: fetch_iana_ports()

    iana_ports = {}
    try:
        with open(PORT_CACHE) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    port = int(row["Port Number"])
                    proto = row["Transport Protocol"].upper()
                    name = row["Service Name"].upper()
                    if proto in ("TCP","UDP"): iana_ports[port] = name
                except: continue
    except Exception as e:
        print(f"[WARN] Could not read IANA cache: {e}")

    full = {**iana_ports, **LOCAL_PORT_SERVICES}
    print(f"[INFO] Loaded {len(LOCAL_PORT_SERVICES)} local + {len(iana_ports)} IANA port services.")
    return full

PORT_SERVICES = load_port_services()
def port_service_name(port):
    try: return PORT_SERVICES.get(int(port), "")
    except: return ""

# ======================================
# DATABASE
# ======================================
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS model_registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT, model_name TEXT, created_at TEXT,
        accuracy REAL, precision REAL, recall REAL, f1 REAL,
        dataset TEXT, model_path TEXT, scaler_path TEXT, features_path TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT, dst_ip TEXT,
        sport INTEGER, dport INTEGER, proto INTEGER, bytes REAL, prob REAL,
        label TEXT, severity TEXT, reason TEXT, source TEXT)""")
    conn.commit(); return conn, cur

conn, cursor = init_db()

# ======================================
# BLACKLIST
# ======================================
def load_blacklist():
    if not os.path.exists(BLACKLIST_PATH):
        print("[WARN] blacklist_ips.txt not found."); return set()
    with open(BLACKLIST_PATH) as f:
        return {normalize_ip(x) for x in f if x.strip()}

# ======================================
# TRAIN MODEL
# ======================================
def train_flow_model(csv_path):
    banner()
    print(f"[INFO] Training Flow model from dataset: {csv_path}")

    start_train = time.time()
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    label_col = next((c for c in ["label","Label","target","y"] if c in df.columns), None)
    if not label_col: raise ValueError("Label column not found!")

    df[label_col] = (df[label_col].astype(str)
        .str.replace(r".*ormal.*","Normal",regex=True)
        .str.replace(r".*alware.*","Malware",regex=True)
        .replace({"benign":"Normal","Benign":"Normal"}))

    df = df[df[label_col].isin(["Normal","Malware"])]
    y = df[label_col].replace({"Normal":0,"Malware":1})
    X = sanitize_dataframe(df.drop(columns=[label_col]).apply(pd.to_numeric, errors="coerce"))
    features = X.columns.tolist()
    json.dump(features, open(FLOW_FEATURES_PATH,"w"), indent=2)

    print(f"[INFO] Training samples: {len(X)}, features: {len(features)}")
    print("[INFO] Fitting StandardScaler and XGBoost model...\n")

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = XGBClassifier(n_estimators=100, max_depth=10, learning_rate=0.1,
                          eval_metric="logloss", n_jobs=-1, verbosity=0)

    for _ in tqdm(range(1), desc="Training Progress", bar_format="{l_bar}{bar} [time left: {remaining}]"):
        model.fit(Xs, y)

    preds = model.predict(Xs)
    acc = accuracy_score(y,preds)
    prec = precision_score(y,preds,zero_division=0)
    rec = recall_score(y,preds,zero_division=0)
    f1 = f1_score(y,preds,zero_division=0)
    duration = time.time() - start_train

    pickle.dump(model, open(FLOW_MODEL_PATH,"wb"))
    pickle.dump(scaler, open(FLOW_SCALER_PATH,"wb"))

    ts = now_ts()
    cursor.execute("""INSERT INTO model_registry (model_name,created_at,accuracy,precision,recall,f1,dataset,model_path,scaler_path,features_path)
                      VALUES (?,?,?,?,?,?,?,?,?,?)""",
                   (f"xgb_{datetime.now():%Y%m%d_%H%M%S}", ts, acc, prec, rec, f1,
                    csv_path, FLOW_MODEL_PATH, FLOW_SCALER_PATH, FLOW_FEATURES_PATH))
    conn.commit()

    print(f"\n✅ [INFO] Training completed in {duration:.2f} seconds.")
    print(f"   Accuracy : {acc:.4f}\n   Precision: {prec:.4f}\n   Recall   : {rec:.4f}\n   F1 Score : {f1:.4f}\n")
    log_alert(f"{ts} [Flow ML Detection] Training completed for Flow model.")
    log_alert(f"{ts} [Flow ML Detection] Accuracy={acc:.4f}, F1={f1:.4f}")

# ======================================
# LOAD MODELS
# ======================================
def load_all_models():
    cursor.execute("SELECT model_path,scaler_path,features_path FROM model_registry ORDER BY id ASC")
    models=[]
    for m in cursor.fetchall():
        try:
            models.append((pickle.load(open(m[0],"rb")),
                           pickle.load(open(m[1],"rb")),
                           json.load(open(m[2]))))
        except Exception as e: log_alert(f"{now_ts()} load_model_error: {e}")
    print(f"[INFO] Loaded {len(models)} models."); return models

# ======================================
# LIVE FLOW DETECTION
# ======================================
def run_live_flow(interface):
    banner()
    print("========== HYBRID FLOW DETECTION ==========")
    log_alert(f"{now_ts()} [Flow ML Detection] Started live flow capture on interface {interface}")
    models = load_all_models(); bl = load_blacklist()

    import pyshark
    cap = pyshark.LiveCapture(interface=interface, display_filter="ip")

    for pkt in cap.sniff_continuously():
        try:
            if not hasattr(pkt,"ip"): continue
            src = normalize_ip(pkt.ip.src); dst = normalize_ip(pkt.ip.dst)
            proto = pkt.transport_layer or "UNK"
            sport = int(getattr(pkt[pkt.transport_layer],"srcport",0)) if hasattr(pkt,pkt.transport_layer) else 0
            dport = int(getattr(pkt[pkt.transport_layer],"dstport",0)) if hasattr(pkt,pkt.transport_layer) else 0
            length = int(getattr(pkt,"length",0)) if hasattr(pkt,"length") else 0
            ssvc,dsvc = port_service_name(sport), port_service_name(dport)

            # ensemble model
            probs=[]
            for model,scaler,features in models:
                row={f:0.0 for f in features}
                for f in features:
                    lf=f.lower()
                    if "proto" in lf: row[f]=proto_to_num(proto)
                    elif "sport" in lf: row[f]=sport
                    elif "dport" in lf: row[f]=dport
                    elif "byte" in lf: row[f]=length
                    elif "pkt" in lf: row[f]=1.0
                Xs=scaler.transform(sanitize_dataframe(pd.DataFrame([row],columns=features)))
                probs.append(model.predict_proba(Xs)[0][1])

            prob=float(np.mean(probs)); label="Malware" if prob>=MODEL_PROB_THRESHOLD else "Normal"
            reason=[]; source="ensemble"

            # blacklist
            if src in bl or dst in bl:
                label="Malware"; reason=["blacklist"]; source="blacklist"
                msg=f"{now_ts()} [Flow ML Detection] Label=Malware, reason=blacklist {src}:{sport}({ssvc})->{dst}:{dport}({dsvc}) prob={prob:.3f}"
                print(msg); log_alert(msg)

            # SYN flood
            if hasattr(pkt,"tcp") and hasattr(pkt,"ip"):
                dport_check=int(pkt.tcp.dstport)
                syn=int(pkt.tcp.flags_syn or 0); ack=int(pkt.tcp.flags_ack or 0)
                ttl=int(pkt.ip.ttl or 0); flen=int(pkt.frame_info.len or 0)
                if (dport_check==80 and syn==1 and ack==0 and ttl==64 and flen==54):
                    if prob>=MODEL_PROB_THRESHOLD:
                        label="Malware"; reason=["SYN-Flood"]; source="rule"
                        msg=f"{now_ts()} [Flow ML Detection] Label=Malware, reason=SYN-Flood {src}:{sport}({ssvc})->{dst}:{dport_check}(HTTP) prob={prob:.3f}"
                    else:
                        label="Normal"; reason=["SYN-Flood (not enough evidence)"]
                        msg=f"{now_ts()} [Flow ML Detection] Label=Normal, reason=SYN-Flood (not enough evidence) {src}:{sport}({ssvc})->{dst}:{dport_check}(HTTP) prob={prob:.3f}"
                    print(msg); log_alert(msg)

            # UDP / NTP flood
            if hasattr(pkt,"udp"):
                dport_check=int(pkt.udp.dstport or 0)
                length_udp=int(pkt.udp.length or 0)
                flen=int(pkt.frame_info.len or 0)
                pdstsvc=port_service_name(dport_check)
                if dport_check not in (53,123) and flen>1000:
                    if prob>=MODEL_PROB_THRESHOLD:
                        label="Malware"; reason=["UDP-Flood"]; source="rule"
                        msg=f"{now_ts()} [Flow ML Detection] Label=Malware, reason=UDP-Flood {src}:{sport}({ssvc})->{dst}:{dport_check}({pdstsvc}) prob={prob:.3f}"
                    else:
                        label="Normal"; reason=["UDP-Flood (not enough evidence)"]
                        msg=f"{now_ts()} [Flow ML Detection] Label=Normal, reason=UDP-Flood (not enough evidence) {src}:{sport}({ssvc})->{dst}:{dport_check}({pdstsvc}) prob={prob:.3f}"
                    print(msg); log_alert(msg)
                if dport_check==123 and length_udp>500 and flen>1000:
                    if prob>=MODEL_PROB_THRESHOLD:
                        label="Malware"; reason=["NTP-Flood"]; source="rule"
                        msg=f"{now_ts()} [Flow ML Detection] Label=Malware, reason=NTP-Flood {src}:{sport}({ssvc})->{dst}:{dport_check}(NTP) prob={prob:.3f}"
                    else:
                        label="Normal"; reason=["NTP-Flood (not enough evidence)"]
                        msg=f"{now_ts()} [Flow ML Detection] Label=Normal, reason=NTP-Flood (not enough evidence) {src}:{sport}({ssvc})->{dst}:{dport_check}(NTP) prob={prob:.3f}"
                    print(msg); log_alert(msg)

            # final log
            sev=severity_from_prob(prob); ts=now_ts()
            if not reason: reason=["Normal"]
            msg=(f"{ts} [Flow ML Detection] {('ALERT' if label=='Malware' else 'INFO '):5}{sev}: "
                 f"{src}:{sport}{f'({ssvc})' if ssvc else ''}->"
                 f"{dst}:{dport}{f'({dsvc})' if dsvc else ''} "
                 f"proto={proto} bytes={length} prob={prob:.3f} label={label} reason={','.join(reason)}")
            print(msg); log_alert(msg)
            cursor.execute("""INSERT INTO predictions (timestamp,src_ip,dst_ip,sport,dport,proto,bytes,prob,label,severity,reason,source)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (ts,src,dst,sport,dport,proto_to_num(proto),length,prob,label,sev,",".join(reason),source))
            conn.commit()
        except KeyboardInterrupt: break
        except Exception as e: log_alert(f"[ERROR] {now_ts()} {e}")

# ======================================
# MAIN
# ======================================
if __name__=="__main__":
    banner()
    p=argparse.ArgumentParser(description="Hybrid Flow ML Detection (XGBoost + Signature)")
    g=p.add_mutually_exclusive_group()
    g.add_argument("-f","--file",help="Train model from CSV")
    g.add_argument("-i","--interface",help="Run live hybrid detection")
    g.add_argument("--test",action="store_true",help="Show summary")
    g.add_argument("--view-db",action="store_true",help="View DB entries")
    a=p.parse_args()

    if a.file: train_flow_model(a.file)
    elif a.interface: run_live_flow(a.interface)
    elif a.test:
        bl=load_blacklist(); cursor.execute("SELECT COUNT(*) FROM model_registry")
        total=cursor.fetchone()[0]
        print(f"[INFO] Models in DB: {total}, Blacklist entries: {len(bl)}")
        print("Mode: Hybrid with signature: SYN, UDP, NTP, Blacklist IP\n")
        for r in cursor.execute("""SELECT timestamp,src_ip,dst_ip,sport,dport,proto,bytes,prob,label,severity,source
                                   FROM predictions ORDER BY id DESC LIMIT 5"""):
            ssvc=port_service_name(r[3]); dsvc=port_service_name(r[4])
            print(f"{r[0]} | {r[1]}:{r[3]}{f'({ssvc})' if ssvc else ''} -> "
                  f"{r[2]}:{r[4]}{f'({dsvc})' if dsvc else ''} | proto={r[5]} bytes={r[6]} | "
                  f"prob={r[7]:.3f} | {r[8]} ({r[9]}) source={r[10]}")
    elif a.view_db:
        print("\n=== Models ===")
        for r in cursor.execute("SELECT id,model_name,accuracy,f1,created_at FROM model_registry ORDER BY id DESC LIMIT 5"):
            print(f"ID={r[0]} | {r[1]} | Acc={r[2]:.4f} | F1={r[3]:.4f} | {r[4]}")
        print("\n=== Recent Predictions ===")
        for r in cursor.execute("""SELECT timestamp,src_ip,dst_ip,sport,dport,prob,label,severity,source
                                   FROM predictions ORDER BY id DESC LIMIT 10"""):
            ssvc=port_service_name(r[3]); dsvc=port_service_name(r[4])
            print(f"{r[0]} | {r[1]}:{r[3]}{f'({ssvc})' if ssvc else ''} -> "
                  f"{r[2]}:{r[4]}{f'({dsvc})' if dsvc else ''} | prob={r[5]:.3f} | {r[6]} ({r[7]}) src={r[8]}")
    else: p.print_help()
