"""
AI-Based Network Intrusion Detection System (NIDS)
A machine learning-powered network intrusion detection system using Random Forest
"""

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import time

# Page Configuration
st.set_page_config(
    page_title="AI Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
    <style>
    .main-header {
        font-size: 42px;
        font-weight: bold;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 10px;
    }
    .sub-header {
        font-size: 18px;
        color: #616161;
        text-align: center;
        margin-bottom: 30px;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.markdown('<div class="main-header">🛡️ AI Network Intrusion Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Machine Learning-Powered Security Monitoring</div>', unsafe_allow_html=True)

# Initialize session state
if 'model' not in st.session_state:
    st.session_state.model = None
if 'model_trained' not in st.session_state:
    st.session_state.model_trained = False
if 'accuracy' not in st.session_state:
    st.session_state.accuracy = 0
if 'training_data' not in st.session_state:
    st.session_state.training_data = None


@st.cache_data
def load_data(simulate=True):
    """
    Load or simulate network traffic data
    
    Parameters:
    simulate (bool): If True, generates synthetic data. If False, loads real dataset.
    
    Returns:
    pd.DataFrame: Network traffic dataset
    """
    if simulate:
        # Generate simulated network traffic data
        np.random.seed(42)
        n_samples = 5000
        
        # Normal traffic features
        normal_packets = np.random.randint(1, 100, n_samples // 2)
        normal_bytes = np.random.randint(100, 5000, n_samples // 2)
        normal_duration = np.random.uniform(0.01, 10, n_samples // 2)
        normal_port = np.random.choice([80, 443, 8080, 22, 21], n_samples // 2)
        normal_label = np.zeros(n_samples // 2)
        
        # Malicious traffic features (anomalies)
        attack_packets = np.random.randint(200, 10000, n_samples // 2)
        attack_bytes = np.random.randint(10000, 100000, n_samples // 2)
        attack_duration = np.random.uniform(20, 100, n_samples // 2)
        attack_port = np.random.choice([1337, 4444, 31337, 6667, 12345], n_samples // 2)
        attack_label = np.ones(n_samples // 2)
        
        # Combine normal and attack traffic
        packets = np.concatenate([normal_packets, attack_packets])
        bytes_transferred = np.concatenate([normal_bytes, attack_bytes])
        duration = np.concatenate([normal_duration, attack_duration])
        port = np.concatenate([normal_port, attack_port])
        labels = np.concatenate([normal_label, attack_label])
        
        # Create DataFrame
        df = pd.DataFrame({
            'packets': packets,
            'bytes': bytes_transferred,
            'duration': duration,
            'port': port,
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
            'flag': np.random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH'], n_samples),
            'label': labels
        })
        
        # Shuffle the data
        df = df.sample(frac=1).reset_index(drop=True)
        
        return df
    else:
        # For loading real dataset (CIC-IDS2017)
        try:
            df = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
            return df
        except FileNotFoundError:
            st.error("Dataset file not found! Using simulated data instead.")
            return load_data(simulate=True)


def preprocess_data(df):
    """
    Preprocess the dataset for machine learning
    
    Parameters:
    df (pd.DataFrame): Raw dataset
    
    Returns:
    tuple: X (features), y (labels)
    """
    # Encode categorical variables
    df_encoded = df.copy()
    
    if 'protocol' in df_encoded.columns:
        df_encoded['protocol'] = df_encoded['protocol'].map({'TCP': 0, 'UDP': 1, 'ICMP': 2})
    
    if 'flag' in df_encoded.columns:
        df_encoded['flag'] = df_encoded['flag'].map({'SYN': 0, 'ACK': 1, 'FIN': 2, 'RST': 3, 'PSH': 4})
    
    # Separate features and labels
    X = df_encoded.drop('label', axis=1)
    y = df_encoded['label']
    
    return X, y


def train_model(X, y):
    """
    Train the Random Forest Classifier
    
    Parameters:
    X: Feature matrix
    y: Target labels
    
    Returns:
    tuple: trained model, accuracy score, test data
    """
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Initialize and train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    
    with st.spinner('Training Random Forest Classifier...'):
        model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Calculate accuracy
    accuracy = accuracy_score(y_test, y_pred)
    
    return model, accuracy, (X_test, y_test, y_pred)


# Sidebar
st.sidebar.title("📊 Control Panel")
st.sidebar.markdown("---")

# Data Source Selection
st.sidebar.subheader("Data Configuration")
data_mode = st.sidebar.radio(
    "Select Data Source:",
    ["Simulated Data", "Real Dataset (CIC-IDS2017)"]
)

# Load Data Button
if st.sidebar.button("🔄 Load/Reload Data"):
    with st.spinner("Loading data..."):
        simulate = (data_mode == "Simulated Data")
        st.session_state.training_data = load_data(simulate=simulate)
        st.sidebar.success(f"✅ Loaded {len(st.session_state.training_data)} records")

# Model Training Section
st.sidebar.markdown("---")
st.sidebar.subheader("Model Training")

if st.sidebar.button("🚀 Train Model Now"):
    if st.session_state.training_data is not None:
        # Preprocess data
        X, y = preprocess_data(st.session_state.training_data)
        
        # Train model
        model, accuracy, test_data = train_model(X, y)
        
        # Store in session state
        st.session_state.model = model
        st.session_state.accuracy = accuracy
        st.session_state.model_trained = True
        st.session_state.test_data = test_data
        
        st.sidebar.success(f"✅ Model Trained! Accuracy: {accuracy*100:.2f}%")
    else:
        st.sidebar.error("⚠️ Please load data first!")

# Display training status
if st.session_state.model_trained:
    st.sidebar.metric("Model Status", "✅ Trained", f"Accuracy: {st.session_state.accuracy*100:.2f}%")
else:
    st.sidebar.metric("Model Status", "⏳ Not Trained", "")

# Main Content Area
st.markdown("---")

# Project Description
with st.expander("📖 About This Project", expanded=True):
    st.write("""
    ### Overview
    This AI-powered Network Intrusion Detection System (NIDS) uses Machine Learning to detect 
    malicious network traffic in real-time. The system employs a **Random Forest Classifier** 
    trained on network flow features to distinguish between normal and attack traffic.
    
    ### Features
    - **Real-time Traffic Analysis**: Monitor network packets and detect anomalies
    - **Machine Learning Detection**: Random Forest algorithm with 100+ decision trees
    - **Interactive Dashboard**: Visualize metrics, confusion matrix, and live predictions
    - **Simulation Mode**: Test the system without requiring real network data
    
    ### How to Use
    1. **Load Data**: Click "Load/Reload Data" in the sidebar
    2. **Train Model**: Click "Train Model Now" to initialize the ML classifier
    3. **Live Testing**: Use the simulator below to test detection capabilities
    """)

# Show dataset info if loaded
if st.session_state.training_data is not None:
    st.markdown("---")
    st.subheader("📊 Dataset Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Records", len(st.session_state.training_data))
    with col2:
        normal_count = len(st.session_state.training_data[st.session_state.training_data['label'] == 0])
        st.metric("Normal Traffic", normal_count)
    with col3:
        attack_count = len(st.session_state.training_data[st.session_state.training_data['label'] == 1])
        st.metric("Attack Traffic", attack_count)
    with col4:
        attack_ratio = (attack_count / len(st.session_state.training_data)) * 100
        st.metric("Attack Ratio", f"{attack_ratio:.1f}%")
    
    # Display sample data
    with st.expander("View Sample Data"):
        st.dataframe(st.session_state.training_data.head(20))

# Model Performance Visualization
if st.session_state.model_trained:
    st.markdown("---")
    st.subheader("🎯 Model Performance")
    
    X_test, y_test, y_pred = st.session_state.test_data
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Confusion Matrix
        st.write("**Confusion Matrix**")
        cm = confusion_matrix(y_test, y_pred)
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Normal', 'Attack'],
                   yticklabels=['Normal', 'Attack'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        st.pyplot(fig)
    
    with col2:
        # Classification Report
        st.write("**Classification Report**")
        report = classification_report(y_test, y_pred, 
                                      target_names=['Normal', 'Attack'],
                                      output_dict=True)
        report_df = pd.DataFrame(report).transpose()
        st.dataframe(report_df.round(3))
        
        # Feature Importance
        st.write("**Feature Importance**")
        feature_importance = pd.DataFrame({
            'feature': X_test.columns,
            'importance': st.session_state.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        fig, ax = plt.subplots(figsize=(8, 4))
        sns.barplot(data=feature_importance, x='importance', y='feature', palette='viridis')
        plt.xlabel('Importance Score')
        plt.ylabel('Features')
        plt.title('Feature Importance')
        st.pyplot(fig)

# Live Traffic Simulator
st.markdown("---")
st.subheader("🔴 Live Traffic Simulator")

if st.session_state.model_trained:
    st.write("Simulate network packets and test the model's detection capabilities:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        packets = st.slider("Number of Packets", 1, 10000, 50)
        bytes_val = st.slider("Bytes Transferred", 100, 100000, 1000)
    
    with col2:
        duration = st.slider("Connection Duration (s)", 0.01, 100.0, 5.0)
        port = st.selectbox("Destination Port", [80, 443, 8080, 22, 21, 1337, 4444, 31337])
    
    with col3:
        protocol = st.selectbox("Protocol", ['TCP', 'UDP', 'ICMP'])
        flag = st.selectbox("TCP Flag", ['SYN', 'ACK', 'FIN', 'RST', 'PSH'])
    
    if st.button("🔍 Analyze Traffic", type="primary"):
        # Prepare input data
        protocol_encoded = {'TCP': 0, 'UDP': 1, 'ICMP': 2}[protocol]
        flag_encoded = {'SYN': 0, 'ACK': 1, 'FIN': 2, 'RST': 3, 'PSH': 4}[flag]
        
        input_data = pd.DataFrame({
            'packets': [packets],
            'bytes': [bytes_val],
            'duration': [duration],
            'port': [port],
            'protocol': [protocol_encoded],
            'flag': [flag_encoded]
        })
        
        # Make prediction
        with st.spinner("Analyzing traffic..."):
            time.sleep(0.5)  # Simulate processing
            prediction = st.session_state.model.predict(input_data)[0]
            probability = st.session_state.model.predict_proba(input_data)[0]
        
        # Display results
        st.markdown("---")
        st.subheader("Detection Result")
        
        if prediction == 1:
            st.error("🚨 **ALERT: MALICIOUS TRAFFIC DETECTED!**")
            st.write(f"**Threat Confidence:** {probability[1]*100:.2f}%")
            st.write("**Recommendation:** Block this connection and investigate further.")
        else:
            st.success("✅ **Normal Traffic - No Threat Detected**")
            st.write(f"**Confidence:** {probability[0]*100:.2f}%")
            st.write("**Status:** Connection appears legitimate.")
        
        # Show probabilities
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Normal Probability", f"{probability[0]*100:.2f}%")
        with col2:
            st.metric("Attack Probability", f"{probability[1]*100:.2f}%")
else:
    st.info("⚠️ Please train the model first to use the live simulator.")

# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666; padding: 20px;'>
        <p>🔒 AI-Powered Network Intrusion Detection System | Built with Streamlit & Scikit-Learn</p>
        <p>For educational and research purposes</p>
    </div>
""", unsafe_allow_html=True)
