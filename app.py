import streamlit as st
import pyshark
import numpy as np
import time
import joblib
import smtplib
from email.message import EmailMessage
import tensorflow as tf
from datetime import datetime
import os

# ----------------------- Load Model & Assets ----------------------- #
@st.cache_resource
def load_model_and_assets():
    model = tf.keras.models.load_model("Full_Model_model.h5")
    scaler = joblib.load("scaler.pkl")
    pca = joblib.load("pca.pkl")
    le = joblib.load("label_encoder.pkl")
    return model, scaler, pca, le

model, scaler, pca, le = load_model_and_assets()

# ----------------------- Utility Functions ----------------------- #
def extract_features(pkt):
    try:
        return [
            len(pkt),
            int(pkt.transport_layer == 'TCP'),
            int(pkt.transport_layer == 'UDP'),
            int(pkt.highest_layer == 'HTTP'),
            int(pkt.highest_layer == 'TLS'),
            float(pkt.sniff_timestamp),
        ]
    except:
        return None

def send_alert(email, message):
    try:
        msg = EmailMessage()
        msg.set_content(message)
        msg['Subject'] = '🔴 Malware Alert Detected!'
        msg['From'] = "akshaygarg0805@gmail.com"
        msg['To'] = email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login("akshaygarg0805@gmail.com", "vqjb poxw bnug tjle")
            smtp.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Email failed: {e}")
        return False

def log_suspicious_packet(pkt, label):
    os.makedirs("logs", exist_ok=True)
    with open("logs/suspicious_packets.log", "a") as f:
        ip = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
        f.write(f"[{datetime.now()}] {label} - Destination IP: {ip} - {pkt.summary()}\n")

# ----------------------- Streamlit UI State ----------------------- #
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False

if 'stop_signal' not in st.session_state:
    st.session_state.stop_signal = False

# ----------------------- Page Navigation ----------------------- #
st.sidebar.title("🔍 Navigation")
page = st.sidebar.radio("Go to", ["🏠 Welcome", "🛡️ Detection", "ℹ️ About"])

# ----------------------- Welcome Page ----------------------- #
if page == "🏠 Welcome":
    st.title("👋 Welcome to MadNet")
    st.markdown("""
    ## 🚀 Real-time Malware Detection
    This tool captures your network packets and classifies them using a trained deep learning model.

    - 📧 Email alerts for malware
    - 🧪 Real-time predictions
    - 📁 Logged suspicious packets

    🔧 Works over local and Wi-Fi interfaces. Choose the right one based on your setup.
    """)

# ----------------------- Detection Page ----------------------- #
elif page == "🛡️ Detection":
    st.title("🛡️ Live Malware Packet Classifier")
    st.markdown("Monitors live network traffic and classifies packets using a trained model.")

    user_email = st.text_input("📧 Enter your email to receive malware alerts:")

    def get_interfaces():
        try:
            cap = pyshark.LiveCapture()
            interfaces = [iface for iface in cap.interfaces]
            cap.close()
            return interfaces
        except Exception as e:
            st.error(f"Failed to list interfaces: {e}")
            return []

    iface_list = get_interfaces()
    iface = st.selectbox("🌐 Select Network Interface", iface_list)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶️ Start Monitoring"):
            st.session_state.monitoring = True
            st.session_state.stop_signal = False
    with col2:
        if st.button("⏹️ Stop Monitoring"):
            st.session_state.stop_signal = True
            st.session_state.monitoring = False

    def start_capture(interface, user_email):
        st.success(f"📡 Capturing on {interface}... Click stop to end.")
        cap = pyshark.LiveCapture(interface=interface)
        for pkt in cap.sniff_continuously():
            if st.session_state.stop_signal:
                st.warning("🛑 Monitoring Stopped.")
                break

            features = extract_features(pkt)
            if features:
                expected_features = scaler.mean_.shape[0]
                if len(features) < expected_features:
                    features += [0] * (expected_features - len(features))
                elif len(features) > expected_features:
                    features = features[:expected_features]

                features_scaled = scaler.transform([features])
                if pca:
                    features_scaled = pca.transform(features_scaled)
                x_input = np.expand_dims(features_scaled, -1)

                pred = model.predict(x_input)
                if pred.shape[1] == 1:
                    pred_label = "Malware" if pred[0][0] > 0.5 else "Benign"
                else:
                    pred_class = np.argmax(pred, axis=1)[0]
                    pred_label = le.inverse_transform([pred_class])[0]

                if "malware" in pred_label.lower():
                    log_suspicious_packet(pkt, pred_label)
                    if user_email:
                        ip = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
                        send_alert(user_email, f"Suspicious packet detected: {pred_label}\nDestination IP: {ip}\n{pkt.summary()}")

                if hasattr(pkt, 'ip'):
                    dst_ip = pkt.ip.dst
                    st.info(f"🌐 Destination IP: **{dst_ip}** — 🧪 Prediction: **{pred_label}**")
                else:
                    st.info(f"🧪 Prediction: **{pred_label}** (No IP info)")

                time.sleep(0.5)

    if st.session_state.monitoring and iface and user_email:
        start_capture(iface, user_email)

# ----------------------- About Page ----------------------- #
elif page == "ℹ️ About":
    st.title("ℹ️ About This Application")
    st.markdown("""
    ## 🧠 What This App Does
    - Real-time malware classification of packets
    - Alerts via email & logs suspicious data

    ## 🧪 Model Info
    - Type: 1D CNN with optional attention
    - Framework: TensorFlow/Keras
    - Output: Binary or multi-class classification

    ## 📊 Features Used
    - Packet length
    - TCP, UDP, HTTP, TLS flags
    - Timestamp

    ## 📁 Dataset
    - Obfuscated-MalMem2022, CIC-MalMem
    - Preprocessed and balanced

    ## 🌐 Interface Guide
    | Interface          | Meaning                               |
    |--------------------|---------------------------------------|
    | eth0 / enpXsY      | Wired Ethernet (LAN)                  |
    | wlan0              | Wireless Wi-Fi                        |
    | lo                 | Loopback (Local machine only)         |
    | nfqueue            | Security/firewall queue               |
    | dbus-system/session| Inter-process communication (ignore)  |
    | randpkt            | Simulated traffic (testing)           |
    | wifidump           | Wi-Fi monitor dump                    |
    | ciscodump/sshdump  | Remote capture for Cisco/SSH          |

    ⚠️ Use "eth0" for LAN, "wlan0" for Wi-Fi. "lo" for local debugging.

    ## 🔌 Common Ports & Usage
    | Port | Protocol | Legitimate Use       | Possible Malware Use   |
    |------|----------|----------------------|-------------------------|
    | 80   | HTTP     | Browsing             | Exfiltration            |
    | 443  | HTTPS    | Secure browsing      | Encrypted C2 commands   |
    | 21   | FTP      | File transfer        | Unauthorized uploads    |
    | 22   | SSH      | Remote shell         | Remote access trojans   |
    | 53   | DNS      | Domain name lookup   | DNS tunneling attacks   |
    """)