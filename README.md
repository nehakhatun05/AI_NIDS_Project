# 🛡️ AI-Based Network Intrusion Detection System (NIDS)

An AI-powered Network Intrusion Detection System using Machine Learning to detect malicious network traffic in real-time.

## 📋 Overview

This project implements a sophisticated Network Intrusion Detection System (NIDS) that leverages Random Forest machine learning algorithm to identify and classify network traffic as either normal or potentially malicious. The system features an interactive web-based dashboard built with Streamlit for real-time monitoring and analysis.

## ✨ Features

- **Machine Learning Detection**: Random Forest Classifier with 100 decision trees
- **Real-time Analysis**: Live traffic simulation and prediction capabilities
- **Interactive Dashboard**: Web-based UI with visualizations and metrics
- **Dual Data Modes**: 
  - Simulated data for immediate testing
  - Support for real-world CIC-IDS2017 dataset
- **Comprehensive Metrics**: Accuracy, confusion matrix, classification reports, and feature importance
- **Visual Analytics**: Heatmaps, bar charts, and performance visualizations

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Web browser (Chrome, Firefox, Edge, etc.)

### Setup Instructions

1. **Clone or navigate to the project directory**:
   ```bash
   cd AI_NIDS_Project
   ```

2. **Install required dependencies**:
   ```bash
   pip install pandas numpy scikit-learn streamlit seaborn matplotlib
   ```

   The following libraries will be installed:
   - `pandas` & `numpy`: Data manipulation and numerical operations
   - `scikit-learn`: Machine learning algorithms (Random Forest)
   - `streamlit`: Web dashboard framework
   - `seaborn` & `matplotlib`: Data visualization

## 🎯 Usage

### Starting the Application

1. **Open terminal in the project directory**:
   ```bash
   cd AI_NIDS_Project
   ```

2. **Launch the Streamlit dashboard**:
   ```bash
   streamlit run nids_main.py
   ```

3. **Access the dashboard**:
   - The application will automatically open in your default browser
   - If not, manually navigate to: `http://localhost:8501`

### Using the Dashboard

#### Step 1: Load Data
- In the sidebar, select your data source:
  - **Simulated Data**: Generates synthetic network traffic (recommended for first-time users)
  - **Real Dataset**: Loads CIC-IDS2017 dataset (if available)
- Click "🔄 Load/Reload Data"

#### Step 2: Train the Model
- Click "🚀 Train Model Now" in the sidebar
- The system will:
  - Split data into training (70%) and testing (30%) sets
  - Train a Random Forest Classifier with 100 trees
  - Display accuracy metrics and performance visualizations

#### Step 3: Test Live Detection
- Use the **Live Traffic Simulator** section to test the model:
  - Adjust network parameters (packets, bytes, duration, port, protocol, flag)
  - Click "🔍 Analyze Traffic"
  - View the detection result and confidence scores

### Understanding Results

- **Green ✅**: Normal traffic detected - connection is safe
- **Red 🚨**: Malicious traffic detected - potential threat identified
- **Confidence Scores**: Probability percentages for each classification
- **Confusion Matrix**: Shows true positives, false positives, true negatives, and false negatives
- **Feature Importance**: Indicates which network features are most influential in detection

## 📊 Dataset Information

### Simulated Data (Default)
The system generates synthetic network traffic with realistic features:
- 5,000 sample records
- 50/50 split between normal and attack traffic
- Features: packets, bytes, duration, port, protocol, TCP flags

### Real Dataset (CIC-IDS2017)
For production testing, you can use the CIC-IDS2017 benchmark dataset:

1. **Download**: [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
2. **Place in project directory**: Copy the CSV file to `AI_NIDS_Project/`
3. **Update code**: In `nids_main.py`, modify the `load_data()` function:
   ```python
   df = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
   ```

## 🏗️ Technical Architecture

### Machine Learning Model
- **Algorithm**: Random Forest Classifier
- **Number of Trees**: 100
- **Max Depth**: 20
- **Train/Test Split**: 70/30 with stratification

### Feature Set
1. **Packets**: Number of packets in the connection
2. **Bytes**: Total bytes transferred
3. **Duration**: Connection duration in seconds
4. **Port**: Destination port number
5. **Protocol**: Network protocol (TCP/UDP/ICMP)
6. **Flag**: TCP flag (SYN/ACK/FIN/RST/PSH)

### Detection Classes
- **0 (Normal)**: Legitimate network traffic
- **1 (Attack)**: Malicious or anomalous traffic

## 🛠️ Troubleshooting

### Common Issues

**1. `streamlit` is not recognized**
   - **Solution**: Python may not be in PATH. Try:
     ```bash
     python -m streamlit run nids_main.py
     ```
   - Or reinstall Python and check "Add Python to PATH" during installation

**2. `ModuleNotFoundError`**
   - **Solution**: Ensure all dependencies are installed:
     ```bash
     pip install pandas numpy scikit-learn streamlit seaborn matplotlib
     ```

**3. Browser doesn't open automatically**
   - **Solution**: Manually open your browser and navigate to `http://localhost:8501`

**4. Port 8501 already in use**
   - **Solution**: Specify a different port:
     ```bash
     streamlit run nids_main.py --server.port 8502
     ```

## 📚 References

- [Python Documentation](https://docs.python.org/)
- [Scikit-Learn Random Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [Visual Studio Code](https://code.visualstudio.com/)

## 🎓 Educational Purpose

This project is designed for:
- Academic research and demonstrations
- Learning machine learning applications in cybersecurity
- Understanding network intrusion detection concepts
- Prototyping ML-based security tools

## 📝 Project Structure

```
AI_NIDS_Project/
│
├── nids_main.py           # Main application file
├── README.md              # This file
└── [dataset.csv]          # Optional: Real dataset file
```

## 🔒 Security Note

This is a prototype system for educational purposes. For production deployment in real network environments, additional considerations are required:
- Real-time packet capture integration
- Performance optimization for large-scale traffic
- Security hardening and access controls
- Continuous model retraining with updated threat data

## 👨‍💻 Development

Built with:
- **Python 3.14**
- **Streamlit 1.52.2**
- **Scikit-Learn 1.8.0**
- **Pandas 2.3.3**
- **NumPy 2.4.0**

## 📄 License

This project is provided for educational and research purposes.

---

**Made with ❤️ for Cybersecurity Education**
