import boto3
import json
import os

REGION = os.getenv("AWS_REGION", "us-east-1")
BATCH_SIZE = 10  # how many checks per LLM call

# Get AWS credentials from environment variables
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Get model ID from environment or use default
MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID",
    "arn:aws:bedrock:us-east-1:050752630384:inference-profile/us.anthropic.claude-3-7-sonnet-20250219-v1:0"
)

# Initialize Bedrock Runtime Client lazily
_client = None

def get_bedrock_client():
    """Get or create Bedrock client with credentials from environment."""
    global _client
    if _client is not None:
        return _client

    # Re-check environment variables (they might have been set after module import)
    access_key = os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_KEY")
    region = os.getenv("AWS_REGION", "us-east-1")

    if access_key and secret_key:
        print(f"✓ Using AWS credentials from environment variables")
        print(f"  Region: {region}")
        _client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
    else:
        # Use default credential chain (IAM role, ~/.aws/credentials, etc.)
        print(f"⚠ Using default AWS credential chain (IAM role, ~/.aws/credentials, etc.)")
        print(f"  Region: {region}")
        print(f"  Note: If this fails, set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
        try:
            _client = boto3.client(
                "bedrock-runtime",
                region_name=region
            )
        except Exception as e:
            print(f"❌ Error initializing Bedrock client: {e}")
            print(f"\nTo fix this, set the following environment variables:")
            print(f"  export AWS_ACCESS_KEY_ID='your-access-key'")
            print(f"  export AWS_SECRET_ACCESS_KEY='your-secret-key'")
            print(f"  export AWS_REGION='us-east-1'")
            raise

    return _client

# Create client instance (will be initialized on first use)
client = None

def call_claude(payload, model_id=MODEL_ID):
    # Ensure client is initialized
    bedrock_client = get_bedrock_client()
    response = bedrock_client.invoke_model(
        modelId=model_id,
        body=json.dumps(payload),
        contentType="application/json",
        accept="application/json",
    )

    # Bedrock returns a "message" object
    raw = response["body"].read().decode("utf-8")
    msg = json.loads(raw)

    # Extract assistant text from content[]
    text_chunks = []
    for part in msg.get("content", []):
        if part.get("type") == "text":
            text_chunks.append(part.get("text", ""))
    full_text = "".join(text_chunks).strip()

    # Now Claude *should* have returned: {"results": [ ... ]}
    try:
        data = json.loads(full_text)
    except json.JSONDecodeError as e:
        # Helpful debug if Claude didn't follow the schema
        raise ValueError(
            f"Claude did not return valid JSON. Parse error: {e}\nRaw text:\n{full_text[:1000]}"
        )

    return data  # <- this now has data["results"]
