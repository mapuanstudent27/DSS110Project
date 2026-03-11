import streamlit as st
import pandas as pd
import joblib
import altair as alt

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="SOC Dashboard", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR PROFESSIONAL LOOK ---
# Importing Cisco-style geometric fonts (Montserrat) and tech fonts (Share Tech Mono)
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700;800&family=Share+Tech+Mono&display=swap');

    /* Apply clean, professional font globally */
    html, body, p, div, h1, h2, h3, h4, h5, h6, li, span, label {
        font-family: 'Montserrat', sans-serif;
    }
    
    /* Main Backgrounds */
    .main { background-color: #F8F9FA; }
    .sidebar .sidebar-content { background-color: #E9ECEF; }

    /* Action Button */
    .stButton>button { 
        width: 100%; 
        border-radius: 5px; 
        height: 3em; 
        background-color: #007BFF; 
        color: white; 
        font-weight: 700;
        letter-spacing: 1px;
    }
    
    /* Make the main title look like a tech hardware logo */
    h1 {
        font-weight: 800 !important;
        letter-spacing: -1px;
        color: #003366 !important;
    }
    
    /* Make the threat percentage look like a terminal readout */
    [data-testid="stMetricValue"] {
        font-family: 'Share Tech Mono', monospace !important;
        color: #111111;
    }
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
        max_value=1500,
        value=850,
        help="Simulates the data payload size. Standard network MTU is 1500 bytes. Abnormally large packets can indicate buffer overflow attempts."
    )
    protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"], help="Communication protocol.")
    duration = st.number_input("Duration (Sec)", min_value=0.0, value=12.5)
    
    st.divider()
    
    st.subheader("Auth Logs")
    logins = st.number_input("Total Attempts", min_value=0, value=3)
    failed_logins = st.number_input(
        "Failed Logins", 
        min_value=0, 
        value=2,
        help="Critical Metric: 0-2 is human error. 3+ is suspected Brute-Force."
    )
    
    st.divider()
    
    st.subheader("Intel & Crypto")
    ip_score = st.slider(
        "IP Reputation Score", 
        0.0, 
        1.0, 
        0.50,
        help="0.0 is trusted. >0.60 is highly suspicious."
    )
    encryption = st.selectbox(
        "Encryption", 
        ["AES", "DES", "Unknown"],
        help="AES: Safe. DES: Warning. Unknown: High Risk."
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

    # --- DOUBLE MAGNITUDE SMOOTHING (BUSINESS LOGIC OVERRIDE) ---
    probability = raw_probability
    
    # Smooth the "Failed Logins" cliff (If IP is safe, scale down the panic of 3 logins)
    if ip_score <= 0.50: 
        if failed_logins == 3:
            probability = raw_probability * 0.55  
        elif failed_logins == 4:
            probability = raw_probability * 0.75  
        elif failed_logins == 5:
            probability = raw_probability * 0.85  
            
    # Smooth the "IP Reputation" cliff (If logins are safe, but IP crosses 0.60, ramp smoothly)
    elif failed_logins <= 2 and ip_score > 0.60:
        smoothing_factor = 0.60 + (ip_score * 0.40) 
        probability = raw_probability * smoothing_factor

    # Cap probability at 99.9% visually
    probability = min(probability, 0.999)

    # --- UNIFIED REASONING ENGINE ---
    # We collect all the red flags independently so they all show up when triggered
    risk_factors = []
    if failed_logins >= 3:
        risk_factors.append(f"**Auth Failure:** {failed_logins} failed attempts detected.")
    if ip_score > 0.60:
        risk_factors.append("**Malicious Origin:** Source IP matched global threat intelligence blacklists.")
    if encryption == "Unknown":
        risk_factors.append("**Evasion Tactics:** Traffic is missing standard encryption logs.")
    if packet_size >= 1200: 
        risk_factors.append("**Payload Anomaly:** Packet size approaches max MTU limit. High probability of heavy payload delivery.")

    # --- THE "NUANCED" RESULTS DISPLAY ---
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
            st.markdown("**Validation Checks Passed:**")
            if failed_logins < 3: st.markdown("- Authentication error rates within normal human limits.")
            if ip_score <= 0.60: st.markdown("- Source IP holds a trusted reputation score.")
            if encryption != "Unknown": st.markdown(f"- Standard {encryption} encryption protocols verified.")
            if packet_size < 1200: st.markdown("- Payload size well within standard MTU limits.")
        
        elif risk_level == "MEDIUM":
            st.write("🚨 **PRE-EMPTIVE ALERT:** The system has detected anomalous activity.")
            st.write("Instead of a total block, the system recommends **MFA Escalation** or a **Temporary Cooldown**.")
            st.markdown("**Detected Risk Factors:**")
            for factor in risk_factors:
                st.markdown(f"- {factor}")
        
        elif risk_level == "CRITICAL":
            st.write("❌ **ACTION TAKEN:** Connection Terminated.")
            st.write("The threat score exceeds the safety threshold for automated defense.")
            st.markdown("**Detected Risk Factors:**")
            for factor in risk_factors:
                st.markdown(f"- {factor}")

    st.divider()
    st.subheader("Feature Contribution")
    
    # SMOOTHED CHART LOGIC
    scaled_login_risk = min(failed_logins / 6.0, 1.0) 
    scaled_packet_risk = min(packet_size / 1500.0, 1.0) 
    
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
    
    chart = alt.Chart(chart_data).mark_bar(color="#007BFF").encode(
        x=alt.X("Feature", sort=None, axis=alt.Axis(labelAngle=0, title=None)), 
        y=alt.Y("Score", axis=alt.Axis(title="Risk Contribution Level"))
    ).properties(height=250)
    
    st.altair_chart(chart, use_container_width=True)

else:
    st.write("👈 Use the Security Console on the left to begin analysis.")

# --- FOOTER ---
st.markdown("<br><br><br><div style='text-align: center; color: gray; font-size: 10px;'>DSS110 | Tuazon, Alano, Alano, Dalisay, Nerizon</div>", unsafe_allow_html=True)
