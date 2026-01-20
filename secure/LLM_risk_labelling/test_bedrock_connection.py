#!/usr/bin/env python3
"""
Test Bedrock connection with environment credentials
"""

import os
import sys
from claude_client import client, MODEL_ID, AWS_REGION

print("=" * 80)
print("Testing AWS Bedrock Connection")
print("=" * 80)
print(f"AWS Region: {AWS_REGION}")
print(f"Model ID: {MODEL_ID}")
print(f"AWS_ACCESS_KEY_ID: {'SET' if os.getenv('AWS_ACCESS_KEY_ID') or os.getenv('AWS_ACCESS_KEY') else 'NOT SET'}")
print(f"AWS_SECRET_ACCESS_KEY: {'SET' if os.getenv('AWS_SECRET_ACCESS_KEY') or os.getenv('AWS_SECRET_KEY') else 'NOT SET'}")
print()

# Test with a simple payload
test_payload = {
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 100,
    "messages": [
        {
            "role": "user",
            "content": [{"type": "text", "text": "Say 'Hello, connection test successful!'"}]
        }
    ]
}

try:
    print("Attempting to call Bedrock...")
    response = client.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps(test_payload),
        contentType="application/json",
        accept="application/json",
    )

    raw = response["body"].read().decode("utf-8")
    msg = json.loads(raw)

    print("✅ Connection successful!")
    print(f"Response: {msg}")

except Exception as e:
    print(f"❌ Connection failed: {e}")
    print(f"Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
