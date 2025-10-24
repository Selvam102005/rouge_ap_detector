from scapy.all import *
import subprocess, threading, time, os, json, datetime, argparse, smtplib
from email.mime.text import MIMEText

import firebase_admin
from firebase_admin import credentials, db, initialize_app, get_app

BASELINE_FILE = "ap_baseline.json"
ALERTS_SEEN_FILE = "alerts_seen.json"
ALERTS_LOG_FILE = "alerts_log.json"
RSSI_STRONGER_THRESHOLD_DB = 10

FIREBASE_KEYFILE = "firebase_key.json"
FIREBASE_DB_URL = 'https://rogue-4818e-default-rtdb.asia-southeast1.firebasedatabase.app/'

try:
    cred = credentials.Certificate(FIREBASE_KEYFILE)
except Exception as e:
    cred = None
    print("[!] Warning: Could not load Firebase credentials:", e)

if cred is not None:
    try:
        get_app()
    except ValueError:
        try:
            initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
            print("[+] Firebase initialized with DB URL:", FIREBASE_DB_URL)
        except Exception as e:
            print("[!] Firebase initialization failed:", e)

def push_to_firebase(newly_seen_dict):
    """Push only newly seen APs to Firebase."""
    try:
        ref = db.reference("/rogues")
        now = int(time.time())
        for bssid, alert in newly_seen_dict.items():
            safe_bssid = bssid.replace(":", "_")
            ref.child(safe_bssid).update({
                "ssid": alert.get("ssid"),
                "bssid": alert.get("bssid"),
                "rssi": alert.get("rssi"),
                "channel": alert.get("channel"),
                "msg": alert.get("msg"),
                "timestamp": alert.get("timestamp"),
                "last_seen": now,
                "active": True
            })
    except Exception as e:
        print("[!] Firebase push failed:", e)

def cleanup_inactive(timeout=120):
    """Mark APs inactive if not seen within timeout."""
    try:
        ref = db.reference("/rogues")
        rogues = ref.get()
        now = int(time.time())
        if rogues:
            for bssid, ap in rogues.items():
                if now - ap.get("last_seen", 0) > timeout:
                    ref.child(bssid).update({"active": False})
    except Exception as e:
        print("[!] Firebase cleanup failed:", e)

EMAIL_FROM = os.environ.get("EMAIL_FROM")
EMAIL_APP_PASSWORD = os.environ.get("EMAIL_APP_PASSWORD")
EMAIL_TO = os.environ.get("EMAIL_TO")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))

def send_email(subject, body):
    if not (EMAIL_FROM and EMAIL_APP_PASSWORD and EMAIL_TO):
        return

    recipients = [e.strip() for e in EMAIL_TO.split(",") if e.strip()]
    if not recipients:
        return

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = ", ".join(recipients)

        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        server.login(EMAIL_FROM, EMAIL_APP_PASSWORD)
        server.sendmail(EMAIL_FROM, recipients, msg.as_string())
        server.quit()
        print("[+] Email sent to", ", ".join(recipients))
    except Exception as e:
        print("[!] Failed to send email:", e)

def iso_now():
    return datetime.datetime.now().isoformat(sep=" ", timespec="seconds")

def load_json(filename):
    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_json(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("[!] Failed to save JSON", filename, e)

def get_rssi(pkt):
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal"):
            return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        pass
    return None

def get_ssid(pkt):
    if pkt.haslayer(Dot11Elt):
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0:
                    return elt.info.decode(errors="ignore") if elt.info else "<hidden>"
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            return "<hidden>"
    return "<no-ssid>"

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        try:
            return json.load(open(BASELINE_FILE))
        except Exception:
            return {}
    return {}

def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

def build_baseline(iface, duration=20):
    print(f"[+] Building baseline for {duration}s on {iface}")
    tmp = {}
    def h(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            try:
                bssid = pkt[Dot11].addr2
            except Exception:
                return
            ssid = get_ssid(pkt)
            rssi = get_rssi(pkt)
            tmp.setdefault(ssid, {})
            tmp[ssid][bssid] = {"bssid": bssid, "rssi": rssi}
    sniff(iface=iface, prn=h, timeout=duration)
    baseline = {ssid: list(macs.values()) for ssid, macs in tmp.items()}
    save_baseline(baseline)
    print("[+] Baseline saved to", BASELINE_FILE)

def channel_hopper(iface, interval=2):
    channels_24 = list(range(1, 14))
    channels_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
    while True:
        for ch in channels_24 + channels_5:
            try:
                subprocess.call(["sudo", "iwconfig", iface, "channel", str(ch)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            time.sleep(interval)

def detect_rogue(pkt, baseline, alerts_seen):
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return

    try:
        bssid = pkt[Dot11].addr2
    except Exception:
        return

    ssid = get_ssid(pkt)
    rssi = get_rssi(pkt)
    channel = None

    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if getattr(elt, "ID", None) == 3 and getattr(elt, "info", None):
                try:
                    channel = elt.info[0]
                except Exception:
                    channel = None
                break
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass

    alert = {
        "ssid": ssid,
        "bssid": bssid,
        "rssi": rssi,
        "channel": channel,
        "timestamp": iso_now()
    }

    if ssid in baseline:
        bssids_whitelist = {x["bssid"] for x in baseline[ssid] if "bssid" in x}
        if bssid not in bssids_whitelist:
            known_rssis = [x.get("rssi") for x in baseline[ssid] if x.get("rssi") is not None]
            known_max = max(known_rssis) if known_rssis else None
            if rssi is not None and known_max is not None and (rssi - known_max) >= RSSI_STRONGER_THRESHOLD_DB:
                alert["msg"] = "POSSIBLE ROGUE - stronger than baseline"
            else:
                alert["msg"] = "NEW BSSID for known SSID"
        else:
            return
    else:
        alert["msg"] = "NEW SSID (no baseline)"

    push_to_firebase({bssid: alert})

    if not any(a.get("bssid") == bssid for a in alerts_seen):
        alerts_seen.append(alert)
        save_json(ALERTS_SEEN_FILE, alerts_seen)
        print("⚠️ Rogue AP Detected:", json.dumps(alert, indent=2))

        if EMAIL_FROM and EMAIL_APP_PASSWORD and EMAIL_TO:
            subject = f"Rogue AP Detected: {ssid} ({bssid})"
            body = f"""
Rogue AP detected!

SSID: {ssid}
BSSID: {bssid}
RSSI: {rssi}
Channel: {channel}
Message: {alert.get('msg')}
Time: {alert['timestamp']}
"""
            send_email(subject, body)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--time", type=int, default=20)
    parser.add_argument("--no-hop", action="store_true")
    args = parser.parse_args()

    if args.baseline:
        build_baseline(args.iface, args.time)
        return

    baseline = load_baseline()
    alerts_seen = load_json(ALERTS_SEEN_FILE)
    if not isinstance(alerts_seen, list):
        alerts_seen = []

    if not args.no_hop:
        t = threading.Thread(target=channel_hopper, args=(args.iface,))
        t.daemon = True
        t.start()

    print("[*] Rogue AP detector running on", args.iface)

    def periodic_cleanup():
        while True:
            cleanup_inactive(timeout=120)
            time.sleep(60)

    t2 = threading.Thread(target=periodic_cleanup)
    t2.daemon = True
    t2.start()

    try:
        sniff(iface=args.iface, prn=lambda pkt: detect_rogue(pkt, baseline, alerts_seen))
    except KeyboardInterrupt:
        print("\n[+] Stopped by user")
    except Exception as e:
        print("[!] Sniffing error:", e)

if __name__ == "__main__":
    main()