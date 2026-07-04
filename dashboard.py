import streamlit as st
import pandas as pd
import json
import os
import time
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List

# Set Streamlit page config
st.set_page_config(
    page_title="AI SOC Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark Theme CSS Injection
st.markdown("""
<style>
    /* Main container background */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    
    /* Headings styling */
    h1, h2, h3 {
        color: #58a6ff !important;
        font-family: 'Outfit', 'Inter', sans-serif;
    }
    
    /* Metrics panel */
    div[data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: bold;
        color: #00ff66;
    }
    div[data-testid="stMetricLabel"] {
        color: #8b949e;
        font-size: 0.9rem;
    }
    
    /* Custom Card container */
    .soc-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    /* Alert badge styling */
    .severity-badge {
        display: inline-block;
        padding: 0.25rem 0.6rem;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
        text-transform: uppercase;
    }
    .sev-critical { background-color: #ff3333; color: white; }
    .sev-high { background-color: #ff6600; color: white; }
    .sev-medium { background-color: #ffcc00; color: black; }
    .sev-low { background-color: #00ccff; color: black; }
    
    /* Custom status dot */
    .status-dot {
        height: 10px;
        width: 10px;
        background-color: #00ff66;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
        box-shadow: 0 0 8px #00ff66;
    }
    .status-dot.inactive {
        background-color: #ff3333;
        box-shadow: 0 0 8px #ff3333;
    }
</style>
""", unsafe_allow_html=True)

# Define file path
ALERTS_FILE = "alerts.json"

# Initialize SOC Agent in session state so it persists across refreshes
if "agent" not in st.session_state:
    try:
        from soc_agent import SOCAgent
        # Auto-detect default interface
        agent = SOCAgent(interface="eth0")
        agent.start()
        st.session_state.agent = agent
        st.session_state.agent_running = True
    except Exception as e:
        st.session_state.agent = None
        st.session_state.agent_running = False
        st.error(f"Error starting background SOC Agent: {e}")

# Helper functions to load and clear alerts
def load_alerts() -> List[Dict]:
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            st.error(f"Error reading alerts file: {e}")
            return []
    return []

def clear_alerts():
    try:
        with open(ALERTS_FILE, "w") as f:
            json.dump([], f, indent=4)
        st.success("Alert history cleared.")
        time.sleep(1)
        st.rerun()
    except Exception as e:
        st.error(f"Error clearing alerts file: {e}")

# Header
col_title, col_status = st.columns([4, 1])
with col_title:
    st.markdown("<h1>🛡️ AI SOC Analyst & Security Operations Center</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#8b949e;'>Real-time network traffic threat detection with automated Google Gemini AI incident investigation.</p>", unsafe_allow_html=True)

with col_status:
    agent_mode = "Simulation Mode (Local Sniff Fallback)"
    status_class = ""
    if st.session_state.get("agent_running", False) and st.session_state.agent:
        mode = st.session_state.agent.capture_engine.mode
        if mode == "live":
            agent_mode = f"Live Sniffing [{st.session_state.agent.interface}]"
        status_dot = '<span class="status-dot"></span>'
    else:
        agent_mode = "Agent Inactive"
        status_dot = '<span class="status-dot inactive"></span>'
        
    st.markdown(f"""
    <div style='text-align: right; padding: 10px; background: #161b22; border-radius: 8px; border: 1px solid #30363d;'>
        <div style='font-size:0.8rem; color:#8b949e;'>SYSTEM STATUS</div>
        <div style='font-weight:bold;'>{status_dot} {agent_mode}</div>
    </div>
    """, unsafe_allow_html=True)

st.write("---")

# Sidebar Controls
st.sidebar.markdown("### ⚙️ Threat Simulator Control Panel")
st.sidebar.info("Use the controls below to inject simulated attacks. The detection engine will process packets, generate alerts, and trigger Gemini AI analysis.")

if st.sidebar.button("💥 Simulate ICMP Ping Flood"):
    if st.session_state.agent:
        st.session_state.agent.capture_engine.trigger_simulated_threat("ping_flood")
        st.sidebar.success("Ping Flood sequence injected!")
        time.sleep(1.5)  # Wait for capture and AI response
        st.rerun()
    else:
        st.sidebar.error("SOC Agent is not running.")

if st.sidebar.button("🔍 Simulate TCP Port Scan"):
    if st.session_state.agent:
        st.session_state.agent.capture_engine.trigger_simulated_threat("port_scan")
        st.sidebar.success("Port Scan sequence injected!")
        time.sleep(1.5)
        st.rerun()
    else:
        st.sidebar.error("SOC Agent is not running.")

if st.sidebar.button("📡 Simulate DNS Data Tunneling"):
    if st.session_state.agent:
        st.session_state.agent.capture_engine.trigger_simulated_threat("dns_tunnel")
        st.sidebar.success("DNS Tunneling queries injected!")
        time.sleep(1.5)
        st.rerun()
    else:
        st.sidebar.error("SOC Agent is not running.")

st.sidebar.write("---")

# Live/Simulation Settings
st.sidebar.markdown("### 🛠️ Configuration")
if st.session_state.agent:
    current_mode = st.session_state.agent.capture_engine.mode
    mode_option = st.sidebar.selectbox("Sniffing Engine Mode", ["live", "simulation"], index=0 if current_mode == "live" else 1)
    if mode_option != current_mode:
        try:
            st.session_state.agent.capture_engine.stop()
            st.session_state.agent.capture_engine.set_mode(mode_option)
            st.session_state.agent.capture_engine.start()
            st.sidebar.success(f"Mode switched to {mode_option}!")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Cannot switch mode: {e}")

st.sidebar.write("---")
if st.sidebar.button("🧹 Clear Alert Log"):
    clear_alerts()

# Main dashboard layout
alerts = load_alerts()

if not alerts:
    st.warning("No security alerts generated yet. Trigger one of the simulated threats on the sidebar to get started!")
else:
    # Convert alerts to DataFrame for analysis
    df = pd.DataFrame(alerts)
    
    # Enrich and parse severity/risk metrics
    def extract_risk_score(row):
        if "ai_analysis" in row and isinstance(row["ai_analysis"], dict):
            return row["ai_analysis"].get("risk_score", 50)
        return 50
    df["risk_score"] = df.apply(extract_risk_score, axis=1)

    # Top Row Metrics
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric("Total Alerts Triggered", len(df))
    with m_col2:
        high_risk_alerts = len(df[df["risk_score"] >= 70])
        st.metric("High/Critical Incidents", high_risk_alerts, delta_color="inverse")
    with m_col3:
        avg_risk = int(df["risk_score"].mean())
        st.metric("Average Risk Score", f"{avg_risk}/100")
    with m_col4:
        top_attacker = df["source_ip"].value_counts().index[0]
        st.metric("Top Source IP", top_attacker)

    st.write("")

    # Visualizations Row
    col_chart1, col_chart2 = st.columns([2, 1])
    
    with col_chart1:
        st.markdown("### 📈 Threat Timeline")
        # Plot alerts over time
        df["time_parsed"] = pd.to_datetime(df["timestamp"])
        df_time = df.groupby(["time_parsed", "alert_type"]).size().reset_index(name="count")
        
        fig_timeline = px.bar(
            df_time, 
            x="time_parsed", 
            y="count", 
            color="alert_type",
            title="Alert Volume over Time",
            color_discrete_sequence=px.colors.qualitative.Bold,
            height=300
        )
        fig_timeline.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#c9d1d9',
            margin=dict(l=20, r=20, t=40, b=20),
            xaxis=dict(gridcolor='#30363d'),
            yaxis=dict(gridcolor='#30363d')
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    with col_chart2:
        st.markdown("### 🎛️ Threat Severity")
        # Pie chart for severity levels
        fig_severity = px.pie(
            df, 
            names="severity", 
            hole=0.4,
            title="Severity Distribution",
            color="severity",
            color_discrete_map={"High": "#ff6600", "Critical": "#ff3333", "Medium": "#ffcc00", "Low": "#00ccff"},
            height=300
        )
        fig_severity.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#c9d1d9',
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_severity, use_container_width=True)

    st.write("---")

    # Alert Table and Investigation Panel
    col_table, col_details = st.columns([3, 2])

    with col_table:
        st.markdown("### 🚨 Threat Alert Log")
        
        # Display simplified table view for selection
        display_df = df[["alert_id", "timestamp", "alert_type", "severity", "source_ip", "risk_score"]].copy()
        
        # Format display elements
        selected_alert_id = st.selectbox(
            "Select an Incident to Investigate:",
            options=display_df["alert_id"].tolist(),
            index=len(display_df) - 1  # default to latest alert
        )
        
        st.dataframe(
            display_df.sort_values("timestamp", ascending=False),
            use_container_width=True,
            column_config={
                "alert_id": "Alert ID",
                "timestamp": "Timestamp",
                "alert_type": "Classification",
                "severity": "Severity",
                "source_ip": "Source IP",
                "risk_score": "Risk Level (AI)"
            },
            hide_index=True
        )

    with col_details:
        # Load the selected alert details
        selected_alert = next((a for a in alerts if a["alert_id"] == selected_alert_id), None)
        
        if selected_alert:
            st.markdown(f"### 🛡️ Incident Report: {selected_alert_id}")
            
            # Severity Indicator
            sev = selected_alert["severity"]
            sev_badge = f'<span class="severity-badge sev-{sev.lower()}">{sev}</span>'
            
            st.markdown(f"""
            <div class="soc-card">
                <div style='display:flex; justify-content:space-between; align-items:center;'>
                    <strong>Classification:</strong> {selected_alert['alert_type']}
                    {sev_badge}
                </div>
                <div style='margin-top: 10px;'>
                    <strong>Source Host:</strong> <code>{selected_alert['source_ip']}</code>
                </div>
                <div>
                    <strong>Total Packets:</strong> {selected_alert['packet_count']}
                </div>
                <div style='margin-top: 10px; font-size: 0.9rem; color: #8b949e; background: #21262d; padding: 10px; border-radius: 4px; border: 1px solid #30363d;'>
                    <strong>Raw Detection Signature:</strong><br>{selected_alert['details']}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Display AI Analyst Investigation
            ai_analysis = selected_alert.get("ai_analysis")
            if ai_analysis:
                st.markdown("#### 🤖 Google Gemini AI SOC Analyst Investigation")
                
                risk = ai_analysis.get("risk_score", 50)
                # Determine progress bar color based on risk score
                if risk >= 75:
                    progress_color = "red"
                elif risk >= 40:
                    progress_color = "orange"
                else:
                    progress_color = "green"
                
                st.markdown(f"""
                <div class="soc-card" style='border-left: 4px solid {progress_color};'>
                    <div style='font-size:0.8rem; color:#8b949e; margin-bottom: 5px;'>AI RISK ASSESSMENT</div>
                    <div style='display:flex; align-items:center; margin-bottom: 15px;'>
                        <span style='font-size: 2.2rem; font-weight:bold; color:{progress_color}; margin-right: 15px;'>{risk}</span>
                        <div style='width: 100%;'>
                            <div style='background-color:#30363d; border-radius:5px; height: 10px; width:100%;'>
                                <div style='background-color:{progress_color}; border-radius:5px; height: 10px; width:{risk}%;'></div>
                            </div>
                        </div>
                    </div>
                    <strong>Incident Summary:</strong>
                    <p style='color:#c9d1d9; font-size:0.95rem;'>{ai_analysis.get('incident_summary')}</p>
                    
                    <strong style='margin-top:15px; display:block;'>Threat Level:</strong> 
                    <span style='color:{progress_color}; font-weight:bold;'>{ai_analysis.get('threat_classification')}</span>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("#### 📝 Recommended SOC Analyst Response Checklist")
                actions = ai_analysis.get("recommended_actions", [])
                for i, action in enumerate(actions, 1):
                    st.checkbox(f"{action}", key=f"action_{selected_alert_id}_{i}")
            else:
                st.warning("No AI investigation report found for this alert.")

# Add manual refresh
st.write("")
if st.button("🔄 Refresh Dashboard Feed"):
    st.rerun()