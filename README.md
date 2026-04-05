# 🛡️ Network Intrusion Detection System (NIDS) using Machine Learning

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> 🚀 A Machine Learning-based Network Intrusion Detection System that classifies network traffic as **Normal** or **Malicious**, trained on the **NSL-KDD dataset** with ~98% accuracy.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Dataset](#-dataset)
- [Installation](#-installation)
- [Usage](#-usage)
- [Results](#-results)
- [Future Enhancements](#-future-enhancements)
- [License](#-license)

---

## 🎯 Overview

This project implements a **Network Intrusion Detection System (NIDS)** using Machine Learning to monitor and classify network traffic.

It helps identify:

- 🔴 Malicious activities (attacks)
- 🟢 Normal network behavior

### 💡 Why NIDS?

| Benefit | Description |
|---------|-------------|
| 🔒 Proactive Security | Detect threats before damage occurs |
| 🤖 Automation | Continuous monitoring without manual effort |
| 📊 Pattern Recognition | Detect known & unknown attacks |
| ⚡ Real-time Detection | Instant classification of traffic |

---

## ✨ Features

### 🔹 Core Features

- Binary classification (**Normal vs Attack**)
- ~98% model accuracy
- Feature scaling & preprocessing
- Model saving/loading using `joblib`

### 🔹 Interactive Capabilities

- 💬 Manual input testing
- 🌐 IP-based traffic analysis
- 📊 Confidence score output
- 🔍 Risk indicators & explanations

### 🔹 Tech Stack

- Python 3.8+
- Scikit-learn (Random Forest)
- StandardScaler
- Joblib

---

## 🏗️ Architecture
```
NIDS-ML/
│
├── data/
│ ├── KDDTrain+.txt
│ └── KDDTest+.txt
│
├── models/
│ ├── nids_model.pkl
│ ├── scaler.pkl
│ └── encoders.pkl
│
├── src/
│ ├── train_model.py
│ ├── predict.py
│ └── test_with_ips.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 📊 Dataset

### 🔹 NSL-KDD Dataset

| Property | Value |
|----------|-------|
| Training Samples | 125,973 |
| Test Samples | 22,544 |
| Features | 41 + label |
| Attack Types | DoS, Probe, R2L, U2R |

### 🔹 Feature Categories

- **Basic** → protocol, service, bytes
- **Content** → login attempts, root access
- **Traffic** → connection patterns
- **Host** → destination-based metrics

---

## 🚀 Installation

### Prerequisites

- Python 3.8+
- pip
- Git (optional)

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