import streamlit as st
import pandas as pd
import json

st.title("AI SOC Analyst Dashboard")
try:
    with open("alerts.json", "r") as file:
        alerts = json.load(file)

    df = pd.DataFrame(alerts)
    st.metric("Total Alerts", len(df))
    st.metric("Latest Source IP", df.iloc[-1]["source_ip"])
    st.metric("Latest Alert Type", df.iloc[-1]["alert_type"])
    st.subheader("Alert History")
    st.dataframe(df)

except:
    st.warning("No alerts found.")