import streamlit as st
import pandas as pd
import joblib

# 1. Load your exported files
model = joblib.load('rf_intrusion_detector.pkl')
preprocessor = joblib.load('data_preprocessor.pkl')

st.title("🛡️ Network Intrusion Detection System")
st.write("Enter the packet details below to check for potential threats.")

# 2. Create web inputs for the user
packet_size = st.number_input("Network Packet Size", min_value=0, value=850)
protocol = st.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"])
logins = st.number_input("Login Attempts", min_value=0, value=6)
duration = st.number_input("Session Duration (seconds)", min_value=0.0, value=12.5)
encryption = st.selectbox("Encryption Used", ["AES", "DES", "Unknown"])
ip_score = st.slider("IP Reputation Score", 0.0, 1.0, 0.88)
failed_logins = st.number_input("Failed Logins", min_value=0, value=4)

if st.button("Analyze Traffic"):
    # 3. Package the inputs into a dataframe
    incoming_data = pd.DataFrame([{
        'network_packet_size': packet_size,
        'protocol_type': protocol,
        'login_attempts': logins,
        'session_duration': duration,
        'encryption_used': encryption,
        'ip_reputation_score': ip_score,
        'failed_logins': failed_logins,
        'browser_type': 'Unknown',
        'unusual_time_access': 1       
    }])
    
    # 4. Align dummy columns (just like the simulation script)
    incoming_dummies = pd.get_dummies(incoming_data)
    expected_columns = preprocessor.feature_names_in_
    for col in expected_columns:
        if col not in incoming_dummies.columns:
            incoming_dummies[col] = 0
    incoming_dummies = incoming_dummies[expected_columns]
    
    # 5. Predict
    processed_data = preprocessor.transform(incoming_dummies)
    probability = model.predict_proba(processed_data)[0][1]
    
    st.subheader(f"Threat Probability: {probability * 100:.2f}%")
    if probability >= 0.65:
        st.error("🚨 INTRUSION DETECTED! Connection Blocked.")
    else:
        st.success("✅ Traffic Cleared. Connection Allowed.")