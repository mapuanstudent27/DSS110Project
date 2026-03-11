import streamlit as st
import pandas as pd
import joblib
import altair as alt

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="SOC Dashboard", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR PROFESSIONAL LOOK ---
st.markdown("""
    <style>
    .main { background-color: #F8F9FA; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #007BFF; color: white; }
    .sidebar .sidebar-content { background-color: #E9ECEF; }
    </style>
    """, unsafe_allow_html=True)

# --- LOAD ASSETS ---
@st.cache_resource 
def load_models():
    model = joblib.load('rf_intrusion_detector.pkl')
    preprocessor = joblib.load('data_preprocessor.pkl')
    return model, preprocessor

model, preprocessor = load_models()

# --- SIDEBAR INPUTS (THE DEFENSE CONSOLE) ---
st.sidebar.header("🛡️ SECURITY CONSOLE")
st.sidebar.markdown("Adjust packet parameters to simulate network traffic.")

with st.sidebar:
    st.subheader("Session Details")
    packet_size = st.number_input(
        "Packet Size (Bytes)", 
        min_value=0, 
        value=850,
        help="Simulates the data payload size. Standard network MTU is 1500 bytes. Abnormally large or tiny packets can indicate buffer overflow attempts or fragmentation evasion."
    )
    protocol = st.selectbox(
        "Protocol", 
        ["TCP", "UDP", "ICMP"],
        help="Communication protocol. TCP is standard web traffic. Attackers often exploit UDP for amplification attacks or ICMP for ping floods."
    )
    duration = st.number_input(
        "Duration (Sec)", 
        min_value=0.0, 
        value=12.5,
        help="How long the connection remained open. Extremely short durations (0-1s) with high data transfer often indicate automated port scanning."
    )
    
    st.divider()
    
    st.subheader("Auth Logs")
    logins = st.number_input(
        "Total Attempts", 
        min_value=0, 
        value=3,
        help="Total number of authentication requests. Adjusting this alongside failed logins helps the system calculate the error-rate ratio."
    )
    failed_logins = st.number_input(
        "Failed Logins", 
        min_value=0, 
        value=2,
        help="Critical Metric: 0-2 is considered standard human error (typos). 3+ crosses the threshold into suspected automated Brute-Force or Dictionary attacks."
    )
    
    st.divider()
    
    st.subheader("Intel & Crypto")
    ip_score = st.slider(
        "IP Reputation Score", 
        0.0, 
        1.0, 
        0.50,
        help="Simulates global Threat Intelligence feeds (e.g., Cisco Talos). 0.0 is a highly trusted, known IP. 1.0 is a blacklisted botnet or malware command center."
    )
    encryption = st.selectbox(
        "Encryption", 
        ["AES", "DES", "Unknown"],
        help="AES: Modern, military-grade standard (Safe). DES: 1970s legacy standard, vulnerable to cracking (Warning). Unknown: Missing security logs or unencrypted, implies active evasion (High Risk)."
    )
    
    analyze_btn = st.button("RUN SECURITY ANALYSIS")

# --- MAIN DISPLAY AREA (RESULTS) ---
st.title("🛡️ Network Defense & Intrusion Analysis")
st.info("System Status: Monitoring Live Traffic. Adjust parameters in the sidebar to test detection.")

if analyze_btn:
    # 1. Package inputs
    incoming_data = pd.DataFrame([{
        'network_packet_size': packet_size, 'protocol_type': protocol, 'login_attempts': logins,
        'session_duration': duration, 'encryption_used': encryption, 'ip_reputation_score': ip_score,
        'failed_logins': failed_logins, 'browser_type': 'Unknown', 'unusual_time_access': 1       
    }])
    
    # 2. Align dummy columns
    incoming_dummies = pd.get_dummies(incoming_data)
    expected_columns = preprocessor.feature_names_in_
    for col in expected_columns:
        if col not in incoming_dummies.columns:
            incoming_dummies[col] = 0
    incoming_dummies = incoming_dummies[expected_columns]
    
    # 3. Predict (Get Raw Probability)
    processed_data = preprocessor.transform(incoming_dummies)
    raw_probability = model.predict_proba(processed_data)[0][1]

    # --- MAGNITUDE SMOOTHING (BUSINESS LOGIC OVERRIDE) ---
    probability = raw_probability
    
    if ip_score <= 0.50: 
        if failed_logins == 3:
            probability = raw_probability * 0.55  
        elif failed_logins == 4:
            probability = raw_probability * 0.75  
        elif failed_logins == 5:
            probability = raw_probability * 0.85  

    # --- THE "NUANCED" RESULTS ENGINE ---
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.metric(label="Calculated Threat Probability", value=f"{probability * 100:.1f}%")
        
        # Color-coded Status Indicator
        if probability < 0.40:
            st.success("STATUS: SECURE")
            risk_level = "LOW"
        elif 0.40 <= probability < 0.75: 
            st.warning("STATUS: SUSPICIOUS ACTIVITY")
            risk_level = "MEDIUM"
        else:
            st.error("STATUS: INTRUSION DETECTED")
            risk_level = "CRITICAL"

    with col_right:
        st.subheader(f"Risk Assessment: {risk_level}")
        
        if risk_level == "LOW":
            st.write("Current traffic behavior matches baseline standard activity. No action required.")
        
        elif risk_level == "MEDIUM":
            st.write("🚨 **PRE-EMPTIVE ALERT:** The system has detected a rise in failed auth attempts.")
            st.write("Instead of a total block, the system recommends **MFA Escalation** or a **Temporary Cooldown**.")
            if failed_logins >= 3:
                st.markdown("- *Reasoning:* While the IP is trusted, 3+ failures exceed normal human error margin.")
        
        elif risk_level == "CRITICAL":
            st.write("🔥 **ACTION TAKEN:** Connection Terminated.")
            st.write("The threat score exceeds the safety threshold for automated defense.")
            if ip_score > 0.7:
                st.markdown("- *Reasoning:* Malicious IP origin detected in conjunction with auth failures.")
            elif failed_logins >= 5:
                st.markdown("- *Reasoning:* Excessive authentication failures consistent with Brute-Force automation.")
            if encryption == "Unknown":
                st.markdown("- *Reasoning:* Traffic is missing standard encryption logs, indicating potential evasion tactics.")

    st.divider()
    st.subheader("Feature Contribution")
    
    # SMOOTHED CHART LOGIC
    scaled_login_risk = min(failed_logins / 6.0, 1.0) 
    scaled_packet_risk = min(packet_size / 2000.0, 1.0) 
    
    # ENCRYPTION RISK LOGIC
    if encryption == "AES":
        crypto_risk = 0.1  # Modern, safe
    elif encryption == "DES":
        crypto_risk = 0.5  # Outdated, moderate risk
    else:
        crypto_risk = 0.9  # Unknown/Obfuscated, high risk
    
    # --- NEW FLAT TEXT CHART ---
    chart_data = pd.DataFrame({
        "Feature": ["Failed Logins", "IP Risk", "Packet Size", "Crypto Risk"],
        "Score": [scaled_login_risk, ip_score, scaled_packet_risk, crypto_risk]
    })
    
    # Altair lets us force the labelAngle to 0 (flat horizontally)
    chart = alt.Chart(chart_data).mark_bar(color="#007BFF").encode(
        x=alt.X("Feature", sort=None, axis=alt.Axis(labelAngle=0, title=None)), 
        y=alt.Y("Score", axis=alt.Axis(title="Risk Contribution Level"))
    ).properties(height=250)
    
    st.altair_chart(chart, use_container_width=True)

else:
    st.write("👈 Use the Security Console on the left to begin analysis.")

# --- FOOTER ---
st.markdown("<br><br><br><div style='text-align: center; color: gray; font-size: 10px;'>DSS110 | Tuazon, Alano, Alano, Dalisay, Nerizon</div>", unsafe_allow_html=True)
