# 🛡️ KavachX: Real-Time Malware Detection from Network Packets

**KavachX** is a real-time malware detection system that captures network packets using [PyShark](https://github.com/KimiNewt/pyshark), extracts essential features, and classifies them using a trained deep learning model (1D CNN). It notifies users via email if a malicious packet is detected and logs all suspicious activity for further analysis.

---

## 📂 Dataset

### 📌 Source
This project uses the **Obfuscated Malware Memory (Obf-MalMem2022)** dataset.

- 📥 [Download from Kaggle](https://www.kaggle.com/datasets/luccagodoy/obfuscated-malware-memory-2022-cic)

### 📑 Description
This dataset contains memory dumps of obfuscated malware and benign software. For this project, the data has been:
- Preprocessed into packet-level features
- Encoded for model consumption
- Optionally transformed using PCA
- Balanced for binary/multiclass classification

---

## ✨ Features Extracted from Packets

- Packet Length
- TCP flag (1 if TCP, else 0)
- UDP flag (1 if UDP, else 0)
- HTTP flag (1 if HTTP, else 0)
- TLS flag (1 if TLS, else 0)
- Timestamp of capture

---

## 📊 Model Details

| Feature              | Value                            |
|----------------------|----------------------------------|
| Architecture         | 1D CNN (with optional attention) |
| Framework            | TensorFlow/Keras                 |
| Input Shape          | PCA-transformed feature vectors  |
| Output               | Binary or multi-class            |
| Training Script      | `main.ipynb`                     |

---

## 🧪 Multi-Model Extension (Optional)

To prepare the dataset for multi-model study:

```python
import pandas as pd
df = pd.read_csv("preprocessed_dataset.csv")
df["model"] = "cnn"  # or "rf", "svm", etc.
df.to_csv("dataset_with_model_column.csv", index=False)
```

## 🚀 How to Use
### 1. 🔁 Clone the Repository
```bash
git clone https://github.com/yashkaushik4/KavachX.git
cd KavachX
```

### 2. 📦 Install Requirements
Ensure Python 3.8+ is installed. Then:
```bash
pip install -r requirements.txt
```

### 3. 🧠 Train the Model
Download the dataset from Kaggle and use main.ipynb provided in the repo to:

Preprocess the dataset

Train the CNN model

Save the model as Full_Model_model.h5, along with scaler.pkl, pca.pkl, and label_encoder.pkl

### 4. ▶️ Run the App
```bash
streamlit run app.py
```

## Email Alerts
The app uses SMTP (Gmail) to send alerts when malware is detected. Update your credentials and consider using an app password:

### ✅ Step-by-Step: Create an App-Specific Password for Gmail
#####⚠️ Important: Do NOT use your actual Gmail password in the code. Instead, generate an App Password as below.
1. Enable 2-Step Verification on your Gmail account:

- Go to: https://myaccount.google.com/security

- Turn on 2-Step Verification

2. Generate an App Password:

- Go to: https://myaccount.google.com/apppasswords

- Sign in if prompted

- Under “Select App,” choose Mail

- Under “Select Device,” choose Other → type KavachX

- Click Generate

- Copy the 16-character password (e.g., abcd efgh ijkl mnop)

3. Use that password in your code (no spaces):
```python
smtp.login("your-email@gmail.com", "abcd efgh ijkl mnop")
# or better
smtp.login("your-email@gmail.com", "abcdefghijklmop")
```

4. ✅ Done! Now your alerts will send securely using Gmail.

💡 You can revoke or regenerate the app password anytime from the same settings page.


## 🖥️ Network Interface Tips
Choose the appropriate interface when starting monitoring:

| Interface | Meaning                    |
|-----------|----------------------------|
| `eth0`    | Wired Ethernet (LAN)       |
| `wlan0`   | Wireless interface (Wi-Fi) |
| `lo`      | Localhost debugging only   |

Avoid using interfaces like dbus-system, randpkt, ciscodump, etc., unless you understand their use.

## 📁 Logs
Detected suspicious packets are logged under:
```bash
logs/suspicious_packets.log

```
Each log includes:

- Timestamp

- Destination IP

- Packet Summary

- Malware Type

  ## 🧠 Architecture Overview

  ┌────────────┐      ┌────────────┐       ┌────────────┐
│ PyShark    │─────▶ Feature     │──────▶ Preprocess  │
│ LiveCapture│      │ Extraction │       │ + PCA      │
└────────────┘      └────────────┘       └────┬───────┘
                                              │
                                  ┌───────────▼────────────┐
                                  │ Trained 1D CNN Model   │
                                  └───────────▲────────────┘
                                              │
                            ┌─────────────────┴─────────────────┐
                            │ Email Alerts + Log Suspicious Data│
                            └───────────────────────────────────┘

## 🛠 Future Improvements
- Add quarantine folder for malware-flagged software

- Add visualization dashboard (e.g., IP frequency heatmap)

- Extend to support ensemble models

- Add Docker support for deployment
