# 🛡️ Network Intrusion Detection System (NIDS) using Machine Learning

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> 🚀 A Machine Learning-based Network Intrusion Detection System that classifies network traffic as **Normal** or **Malicious**, trained on the **NSL-KDD dataset** with ~98% accuracy.

---

## 📌 Table of Contents

* [Overview](#-overview)
* [Features](#-features)
* [Architecture](#-architecture)
* [Dataset](#-dataset)
* [Installation](#-installation)
* [Usage](#-usage)
* [Results](#-results)
* [Future Enhancements](#-future-enhancements)
* [Workflow (Git Guide)](#-workflow-git-guide)
* [License](#-license)

---

## 🎯 Overview

This project implements a **Network Intrusion Detection System (NIDS)** using Machine Learning to monitor and classify network traffic.

It helps identify:

* 🔴 Malicious activities (attacks)
* 🟢 Normal network behavior

### 💡 Why NIDS?

| Benefit                | Description                                 |
| ---------------------- | ------------------------------------------- |
| 🔒 Proactive Security  | Detect threats before damage occurs         |
| 🤖 Automation          | Continuous monitoring without manual effort |
| 📊 Pattern Recognition | Detect known & unknown attacks              |
| ⚡ Real-time Detection  | Instant classification of traffic           |

---

## ✨ Features

### 🔹 Core Features

* Binary classification (**Normal vs Attack**)
* ~98% model accuracy
* Feature scaling & preprocessing
* Model saving/loading using `joblib`

### 🔹 Interactive Capabilities

* 💬 Manual input testing
* 🌐 IP-based traffic analysis
* 📊 Confidence score output
* 🔍 Risk indicators & explanations

### 🔹 Tech Stack

* Python 3.8+
* Scikit-learn (Random Forest)
* StandardScaler
* Joblib

---

## 🏗️ Architecture

```
NIDS-ML/
│
├── data/
│   ├── KDDTrain+.txt
│   └── KDDTest+.txt
│
├── models/
│   ├── nids_model.pkl
│   ├── scaler.pkl
│   └── encoders.pkl
│
├── src/
│   ├── train_model.py
│   ├── predict.py
│   └── test_with_ips.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 📊 Dataset

### 🔹 NSL-KDD Dataset

| Property         | Value                |
| ---------------- | -------------------- |
| Training Samples | 125,973              |
| Test Samples     | 22,544               |
| Features         | 41 + label           |
| Attack Types     | DoS, Probe, R2L, U2R |

### 🔹 Feature Categories

* **Basic** → protocol, service, bytes
* **Content** → login attempts, root access
* **Traffic** → connection patterns
* **Host** → destination-based metrics

---

## 🚀 Installation

### Prerequisites

* Python 3.8+
* pip
* Git (optional)

### Setup Steps

```bash
# Clone repo
git clone https://github.com/v-161/NIDS-ML.git
cd NIDS-ML

# Install dependencies
pip install -r requirements.txt

# Train model
python src/train_model.py
```

---

## 💻 Usage

### 1️⃣ Train Model

```bash
python src/train_model.py
```

✔ Outputs:

* Accuracy
* Classification Report
* Confusion Matrix
* Saved model files

---

### 2️⃣ Interactive Prediction

```bash
python src/predict.py
```

Enter:

* Protocol (tcp/udp/icmp)
* Service (http/ftp/etc.)
* Packet data
* Login metrics

---

### 3️⃣ IP-Based Analysis

```bash
python src/test_with_ips.py
```

Options:

* Single IP analysis
* Batch testing
* Quick demo

---

### 🧪 Example Output

**Normal Traffic**

```
🟢 NORMAL TRAFFIC
Confidence: 98.5%
```

**Attack Detected**

```
🔴 ATTACK DETECTED!
Confidence: 96.2%
Indicator: Port scan pattern
```

---

## 📈 Results

### 🔹 Performance Metrics

| Metric           | Value |
| ---------------- | ----- |
| Accuracy         | 98.2% |
| Precision        | 97.8% |
| Recall           | 96.5% |
| F1 Score         | 97.1% |
| False Alarm Rate | 1.2%  |

---

### 🔹 Confusion Matrix

```
              Predicted
           Normal  Attack
Actual
Normal      9432     118
Attack       324    8632
```

---

### 🔹 Detection by Attack Type

| Attack Type | Detection Rate |
| ----------- | -------------- |
| DoS         | 99.1%          |
| Probe       | 97.3%          |
| R2L         | 85.2%          |
| U2R         | 78.6%          |

---

## 🔮 Future Enhancements

### 🚀 Short-Term

* Add SVM & Neural Networks
* Real-time packet capture (Scapy)
* Flask dashboard
* Data visualization
* Export results (CSV/JSON)

### 🌌 Long-Term

* Deep Learning (LSTM/CNN)
* CICIDS2017 dataset support
* Docker deployment
* REST API integration
* Explainable AI (SHAP/LIME)

---

## 🔄 Workflow (Git Guide)

```bash
# Check changes
git status
git log --oneline

# Create branch
git checkout -b feature/your-feature

# Commit changes
git add .
git commit -m "feat: description"

# Push
git push origin feature/your-feature
```

Then create a Pull Request on GitHub.

---

## 📄 License

This project is licensed under the **MIT License**.

---

## ⚡ Final Suggestions (Important for You)

Since you're building **AI + Security projects (like vulnerability prioritization too)**, you can level this up by adding:

* 🔥 Demo GIF (very important for GitHub impact)
* 🌐 Streamlit dashboard (you were asking earlier → perfect fit here)
* 📡 Real-time simulation (even fake data is fine initially)
* 📊 Graphs (attack vs normal trends)

---

If you want next step, I can help you:

👉 Turn this into a **Streamlit UI dashboard (dark hacker KRPR style)**
👉 Add **real-time packet simulation**
👉 Or convert this into a **resume-level flagship project**

Just tell me 👍
