# Zenith | Encrypted Traffic Threat Detection

![Zenith Dashboard](https://raw.githubusercontent.com/shadcn-ui/ui/main/apps/www/public/og.png)

Zenith is a high-performance network security engine designed to detect threats in encrypted traffic (SSL/TLS) without decryption. It leverages **XGBoost** machine learning models and **NFStream** for deep packet inspection and statistical feature extraction.

## 🚀 Key Features

- **Encrypted Inspection:** Detects malware, C2 callbacks, and exfiltration in encrypted streams using statistical flow analysis.
- **Deep Telemetry:** Real-time extraction of 80+ network features per flow.
- **XGBoost Intelligence:** Pre-trained binary classifier optimized for low false-positive rates.
- **Premium Dashboard:** State-of-the-art SOC (Security Operations Center) dashboard built with React, Radix UI, and Framer Motion.
- **Windows Optimized:** Robust handling of system-level Npcap dependencies with graceful failover.

## 🛠️ Architecture

- **Backend:** FastAPI (Python 3.12+)
- **Analysis:** NFStream (C-based performance core)
- **Model:** XGBoost + Scikit-learn
- **Frontend:** Vite + React + Tailwind CSS
- **Visualization:** Recharts (Radar, Pie, Bar)

## 📦 Installation

### Prerequisites
- **Python 3.10+**
- **Node.js 18+**
- **Npcap (Windows Only):** [Download Npcap](https://npcap.com/). Ensure "WinPcap API-compatible Mode" is enabled during installation.

### Setup
1. **Clone and Install Backend:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Setup Frontend:**
   ```bash
   cd frontend
   npm install
   ```

## 🚦 Usage

1. **Start the Engine (API):**
   ```bash
   uvicorn src.api.main:app --reload --port 8000
   ```
2. **Start the Command Center (UI):**
   ```bash
   cd frontend
   npm run dev
   ```
3. **Analyze:** Upload a `.pcap` or `.pcapng` file to the dashboard.

## 📁 Project Structure

- `src/api/` - FastAPI endpoints and routing.
- `src/features/` - Traffic feature mapping and extraction logic.
- `models/` - Trained XGBoost artifacts and scalers.
- `frontend/` - React application source code.
- `scripts/` - Utilities for training and dataset preparation.

---
**Disclaimer:** This tool is for research and administrative purposes. Always ensure you have authorization before monitoring network data.
