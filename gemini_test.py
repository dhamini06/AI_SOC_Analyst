from google import genai

import os

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="You are a SOC analyst. Explain what high ICMP activity may indicate."
)

print(response.text)
