import pyshark
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from utils import log_packet, send_email_alert

# Load model and preprocessing objects
model = load_model("Full_Model_model.h5")
scaler = joblib.load("scaler.pkl")
pca = joblib.load("pca.pkl")
le = joblib.load("label_encoder.pkl")

def extract_packet_features(pkt):
    try:
        length = int(pkt.length)
        proto = pkt.transport_layer
        proto = 6 if proto == 'TCP' else 17 if proto == 'UDP' else 1
        src_port = int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, pkt.transport_layer) else 0
        dst_port = int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, pkt.transport_layer) else 0

        features = [length, proto, src_port, dst_port]
        features += [0] * (50 - len(features))  # pad
        return np.array(features[:50])
    except:
        return None

def classify_packet(pkt):
    feat = extract_packet_features(pkt)
    if feat is None:
        return

    x = scaler.transform([feat])
    x = pca.transform(x)
    x = np.expand_dims(x, -1)
    preds = model.predict(x)
    pred_class = np.argmax(preds, axis=1)[0]
    label = le.inverse_transform([pred_class])[0]
    
    print(f"[🔎] Packet classified as: {label}")

    if label.lower() != "benign":
        log_packet(label, feat)
        send_email_alert(label, feat)

def run_live(interface='Wi-Fi'):
    print(f"📡 Sniffing on interface: {interface}")
    cap = pyshark.LiveCapture(interface=interface)
    for pkt in cap.sniff_continuously():
        classify_packet(pkt)

# run_live()  # Uncomment to run
