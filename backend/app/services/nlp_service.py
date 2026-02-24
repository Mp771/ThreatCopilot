import re
import os
import json
from dotenv import load_dotenv
from google import genai

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
USE_GEMINI = os.getenv("USE_GEMINI", "false").lower() == "true"

client = genai.Client(api_key=API_KEY) if API_KEY and USE_GEMINI else None
SESSION_CONTEXT = {}


def rule_based_parser(nl_query: str, previous: dict):
    nl_query = nl_query.lower()
    structured = previous.copy()

    if "failed" in nl_query:
        structured["event"] = "failure"

    if "malware" in nl_query:
        structured["event"] = "malware_detected"

    if "vpn" in nl_query:
        structured["protocol"] = "vpn"

    if "ssh" in nl_query:
        structured["protocol"] = "ssh"

    if "last 24" in nl_query:
        structured["time_range"] = "last_24h"

    if "yesterday" in nl_query:
        structured["time_range"] = "yesterday"
    
    if "brute" in nl_query:
        structured["event"] = "failure"

    threshold_match = re.search(r"more than (\d+)", nl_query)
    if threshold_match:
        structured["threshold"] = int(threshold_match.group(1))

    return structured


def llm_parse(nl_query: str):
    if not client:
        return None

    prompt = f"""
    You are a SOC investigation assistant.
    Convert the following query into STRICT JSON.

    Required keys:
    event, protocol, user, time_range, threshold

    If unknown, use null.

    Query:
    {nl_query}
    """

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        candidates = response.candidates

        if not candidates:
            return None

        first_candidate = candidates[0]

        if not first_candidate.content or not first_candidate.content.parts:
            return None

        part = first_candidate.content.parts[0]

        if not hasattr(part, "text") or not part.text:
            return None

        raw_text = part.text

        start = raw_text.find("{")
        end = raw_text.rfind("}") + 1
        json_text = raw_text[start:end]

        return json.loads(json_text)

    except Exception as e:
        print("LLM parsing failed:", e)
        return None


def normalize_event(event: str | None):
    if not event:
        return None

    event = event.lower()

    if "brute" in event:
        return "failure"

    if "failed" in event:
        return "failure"

    if "malware" in event:
        return "malware_detected"

    return event


def parse_query(nl_query: str, session_id: str = "default"):
    previous = SESSION_CONTEXT.get(session_id, {
        "event": None,
        "protocol": None,
        "user": None,
        "time_range": None,
        "threshold": None
    })

    llm_result = llm_parse(nl_query) if USE_GEMINI else None

    if llm_result:
        structured = {**previous, **llm_result}
    else:
        structured = rule_based_parser(nl_query, previous)

    # 🔥 Normalize event AFTER merging
    structured["event"] = normalize_event(structured.get("event"))

    # 🔥 Force threshold to int safely
    if structured.get("threshold") is not None:
        try:
            structured["threshold"] = int(structured["threshold"])
        except:
            structured["threshold"] = None

    SESSION_CONTEXT[session_id] = structured

    return structured
