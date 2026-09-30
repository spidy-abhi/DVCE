import os

import requests


API_URL = "https://us-llm-1.na.uis.unisys.com/api/generate"
MODEL_NAME = "phi4:14b"


def prompt_athena(content: str) -> str:
    auth_token = os.getenv("ATHENA_AUTH_TOKEN")
    if not auth_token:
        raise RuntimeError("ATHENA_AUTH_TOKEN is not configured")

    prompt_text = f"""
You are a helpful and intelligent chatbot assistant.

User Request:

{content}
"""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt_text,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }

    response = requests.post(API_URL, headers=headers, json=payload, timeout=120)
    response.raise_for_status()
    result = response.json()
    model_response = result.get("response")
    if not isinstance(model_response, str):
        raise ValueError("Athena response did not contain a text 'response' field")
    return model_response