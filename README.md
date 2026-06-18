# AI SOC Analyst Dashboard

## Overview

AI SOC Analyst Dashboard is a cybersecurity monitoring project that captures network traffic, detects suspicious activity, generates alerts, and uses Google Gemini AI to provide automated security analysis.

The project combines packet monitoring, threat detection, AI-powered investigation, JSON alert storage, and a Streamlit dashboard for visualization.

## Features

* ICMP Activity Detection
* DNS Activity Detection
* AI-Powered Alert Analysis using Gemini
* Dynamic Alert IDs
* JSON Alert Storage
* Streamlit Dashboard
* GitHub Integration

## Technologies Used

* Python
* TShark
* Streamlit
* Google Gemini API
* JSON
* Git & GitHub
* Kali Linux

## Project Architecture

Packet Capture (TShark)

↓

Protocol Parsing

↓

Threat Detection

* ICMP Detection
* DNS Detection

↓

Alert Generation

↓

Gemini AI Analysis

↓

JSON Storage

↓

Streamlit Dashboard

## Installation

Clone the repository:

```bash
git clone https://github.com/dhamini06/AI_SOC_Analyst.git
cd AI_SOC_Analyst
```

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the SOC Agent:

```bash
python soc_agent.py
```

Run the Dashboard:

```bash
streamlit run dashboard.py
```

## Sample Alerts

* High ICMP Activity
* High DNS Activity
* AI-generated Threat Classification
* Risk Scoring
* Incident Summary

## Future Enhancements

* Real-time Monitoring
* Multiple Threat Signatures
* Email Notifications
* SIEM Integration
* Threat Intelligence Feeds

## Author

Dhamini

Cyber Security Student

Madanapalle Institute of Technology and Science
