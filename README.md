# Web-Based ADS-B Spoofing Detection System

## ✈️ Overview
This project addresses critical vulnerabilities in **Automatic Dependent Surveillance-Broadcast (ADS-B)**, the backbone of modern air traffic control. Because ADS-B messages are unencrypted, they are susceptible to **spoofing attacks**, where malicious actors inject "ghost planes" into airspace. This system provides a real-time, machine-learning-driven solution to detect and visualize these cybersecurity threats.

## 🚀 Key Features
*   **Intelligent Detection:** Employs the **Isolation Forest** machine learning algorithm to identify anomalies in aircraft trajectories and velocities.
*   **Live Radar Dashboard:** A dynamic web interface (Flask/JavaScript) that visualizes aircraft movement and flags security events in real-time.
*   **Hybrid Data Approach:** Trained on a "gold standard" of real-world flight data from the **OpenSky Network** combined with synthetic attack scenarios.
*   **High Performance:** Achieves **92.5% F1-score** and **94% precision** with an average processing latency of **120ms**.

## 🛠️ Tech Stack
*   **Backend:** Python, Flask
*   **Machine Learning:** Scikit-learn (Isolation Forest)
*   **Frontend:** HTML5, CSS3, JavaScript (Canvas-based radar visualization)
*   **Data Management:** JSON persistent state files

## 📊 Performance
The system was evaluated against spoofing, replay, and message injection attacks, demonstrating:
*   **Precision:** 94% 
*   **Recall:** 91%
*   **Speed:** Real-time responsiveness for aviation monitoring.

## ⚠️ Disclaimer
This is a research project for simulation and educational purposes only.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
markdown## ⚙️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com
   cd Secure-ADB-S
   ```

2. **Install Dependencies:**
   It is recommended to use a virtual environment.
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run the Application:**
   ```bash
   python app.py
   ```
   *Access the dashboard at `http://127.0.0.1:5000`*
