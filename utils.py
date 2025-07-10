import pandas as pd
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

LOG_FILE = "malware_log.csv"

# Logging Function
def log_packet(label, features):
    data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Prediction": label,
        "Features": str(features)
    }
    df = pd.DataFrame([data])
    df.to_csv(LOG_FILE, mode='a', header=not pd.read_csv(LOG_FILE).empty if LOG_FILE else True, index=False)

# Email Alert Function
def send_email_alert(label, features, to_email="gargakshay0805@gmail.com"):
    sender_email = "akshaygarg0805@gmail.com"
    sender_password = "vqjb poxw bnug tjle"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "⚠️ Malware Detected on Your Network!"

    body = f"🚨 Malware Detected\n\nPrediction: {label}\nFeatures: {features}\nTime: {datetime.now()}"
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print("📩 Email alert sent!")
    except Exception as e:
        print("❌ Email error:", e)
