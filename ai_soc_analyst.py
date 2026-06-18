import json
from google import genai

client = genai.Client(
    api_key="YOUR_API_KEY"
)

alert = {
    "alert_type": "High ICMP Activity",
    "severity": "Medium",
    "source_ip": "10.0.2.5",
    "packet_count": 4
}

prompt = f"""
You are a Junior SOC Analyst.

Analyze this security alert:

{json.dumps(alert, indent=4)}

Provide:

1. Threat Classification
2. Severity
3. Risk Score (0-100)
4. Recommended Actions
5. Incident Summary
"""

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt
)

print(response.text)
