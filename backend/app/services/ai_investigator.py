import google.generativeai as genai
import os

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

model = genai.GenerativeModel(
    "gemini-1.5-flash"
)


def generate_report(alert, evidence):

    prompt = f"""
    Analyze this security alert.

    Alert Type:
    {alert['alert_type']}

    Severity:
    {alert['severity']}

    Source IP:
    {alert['source_ip']}

    Connection Count:
    {evidence['connection_count']}

    Top Destinations:
    {evidence['top_destinations']}

    Top Ports:
    {evidence['top_ports']}

    Provide:

    1. Summary
    2. Possible Causes
    3. Risk Assessment
    4. Recommended Actions
    """

    response = model.generate_content(
        prompt
    )

    return response.text