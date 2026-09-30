import os

import requests


    response = requests.post(API_URL, headers=headers, json=payload, timeout=120)
    response.raise_for_status()
    result = response.json()
    model_response = result.get("response")
    if not isinstance(model_response, str):
        raise ValueError("Athena response did not contain a text 'response' field")
    return model_response
