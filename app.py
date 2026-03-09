import streamlit as st
import pandas as pd
import joblib

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Intrusion Detection", page_icon="🛑", layout="centered")

# --- LOAD ASSETS ---
@st.cache_resource 
def load_models():
    model = joblib.load('rf_intrusion_detector.pkl')
    preprocessor = joblib.load('data_preprocessor.pkl')
    return model, preprocessor

model, preprocessor = load_models()

# --- MAIN UI ---
st.title("🛑 NETWORK INTRUSION DETECTION")
st.markdown("Monitor raw session characteristics. Hover over the **'?'** icons for parameter details.")
st.divider()

# --- INPUT COLUMNS ---
col1, col2 = st.columns(2)

with col1:
    packet_size = st.number_input("Network Packet Size (Bytes)", min_value=0, value=850, 
                                  help="Size of the data packet. Standard MTU is up to 1500 bytes. Abnormal sizes may indicate payload fragmentation.")
    protocol = st.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"], 
                            help="Communication protocol. ICMP is often exploited in ping floods.")
    logins = st.number_input("Total Login Attempts", min_value=0, value=6, 
                             help="Total authentication attempts during the session.")
    duration = st.number_input("Session Duration (Seconds)", min_value=0.0, value=12.5, 
                               help="Duration the connection remained open. 0 indicates an instantly killed connection.")

with col2:
    ip_score = st.slider("IP Reputation Score", 0.0, 1.0, 0.88, 
                         help="Risk score based on global threat feeds. 0.0 is safe, 1.0 is highly malicious.")
    failed_logins = st.number_input("Failed Logins", min_value=0, value=4, 
                                    help="Unsuccessful authentication attempts. High numbers strongly indicate brute-force attacks.")
    encryption = st.selectbox("Encryption Used", ["AES", "DES", "Unknown"], 
                              help="Cryptographic protocol detected. 'Unknown' often implies missing/bypassed security logs.")

st.divider()

# --- PREDICTION LOGIC ---
if st.button("EXECUTE TRAFFIC ANALYSIS", type="primary", use_container_width=True):
    
    # Package inputs
    incoming_data = pd.DataFrame([{
        'network_packet_size': packet_size, 'protocol_type': protocol, 'login_attempts': logins,
        'session_duration': duration, 'encryption_used': encryption, 'ip_reputation_score': ip_score,
        'failed_logins': failed_logins, 'browser_type': 'Unknown', 'unusual_time_access': 1       
    }])
    
    # Align dummy columns
    incoming_dummies = pd.get_dummies(incoming_data)
    expected_columns = preprocessor.feature_names_in_
    for col in expected_columns:
        if col not in incoming_dummies.columns:
            incoming_dummies[col] = 0
    incoming_dummies = incoming_dummies[expected_columns]
    
    # Predict
    processed_data = preprocessor.transform(incoming_dummies)
    probability = model.predict_proba(processed_data)[0][1]
    
    # --- DYNAMIC RESULTS DISPLAY ---
    st.subheader("SYSTEM OUTPUT")
    st.progress(float(probability), text=f"Calculated Threat Probability: {probability * 100:.2f}%")
    
    if probability >= 0.65:
        st.error("🚨 CRITICAL: INTRUSION DETECTED. CONNECTION TERMINATED.")
        
        # Dynamic Reasoning Expander
        with st.expander("VIEW THREAT DETAILS & REASONING", expanded=True):
            st.write("Session terminated: Threat probability exceeds the **65% security threshold**.")
            st.write("**Primary Risk Factors Identified:**")
            if failed_logins > 1:
                st.markdown(f"- **Brute-Force Indicator:** {failed_logins} failed login attempts detected.")
            if ip_score > 0.5:
                st.markdown(f"- **Malicious IP Origin:** IP Reputation Score ({ip_score}) matches known threat intelligence blacklists.")
            if encryption == "Unknown":
                st.markdown("- **Log Evasion:** Absence of standard AES/DES encryption data implies potential traffic obfuscation.")
    else:
        st.success("✅ TRAFFIC CLEARED. CONNECTION ESTABLISHED.")
        with st.expander("VIEW CLEARANCE DETAILS"):
            st.write("Session approved: Threat probability is below the **65% security threshold**.")
            if ip_score < 0.5:
                st.markdown("- **Trusted Origin:** IP address holds a safe reputation score.")
            if failed_logins == 0:
                st.markdown("- **Clean Authentication:** No failed login attempts detected.")

# --- FOOTER ---
st.markdown("---")
st.markdown("<div style='text-align: center; color: #888888; font-size: 12px;'>", unsafe_allow_html=True)
st.markdown("**DSS110 PROJECT CREATORS & CONTRIBUTORS:**")
st.markdown("Tuazon, Joshua Aaron V. | Alano, Gwynelle Jazmine | Alano, Gwynette Janize | Dalisay, Katrina | Nerizon, Karla Ysabel")
st.markdown("Data powered by the [Cybersecurity Intrusion Detection Dataset](https://www.kaggle.com/datasets/dnkumars/cybersecurity-intrusion-detection-dataset/data) via Kaggle.")
st.markdown("</div>", unsafe_allow_html=True)
