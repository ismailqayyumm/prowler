#!/usr/bin/env python3
"""
Azure Check Risk Labeling using MITRE ATT&CK Framework

This script processes Azure security checks from CSV and labels them with
MITRE ATT&CK techniques using Claude LLM via AWS Bedrock.
"""

import pandas as pd
import json
import sys
import os
from pathlib import Path

# Load environment variables from .env if available
try:
    from load_env import load_env_file
    load_env_file()
except ImportError:
    pass

from claude_client import call_claude
from azure_prompts import build_user_prompt

BATCH_SIZE = 10

# Path to Azure CSV (relative to this script's directory)
AZURE_CSV_PATH = "../opensearch_work/data/azure_checks_extracted_20260120_214536.csv"
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


def load_azure_checks(csv_path):
    """Load Azure checks from CSV file."""
    csv_file = Path(__file__).parent.parent / csv_path.lstrip("../")

    if not csv_file.exists():
        # Try to find the latest Azure CSV
        data_dir = csv_file.parent
        azure_files = list(data_dir.glob("azure_checks_extracted_*.csv"))
        if azure_files:
            csv_file = max(azure_files, key=lambda p: p.stat().st_mtime)
            print(f"Using latest Azure CSV: {csv_file}")
        else:
            raise FileNotFoundError(f"Azure CSV not found: {csv_file}")

    df = pd.read_csv(csv_file)
    print(f"Loaded {len(df)} Azure checks from {csv_file}")
    return df


def prepare_check_batch(df_batch):
    """Prepare check batch for LLM processing."""
    check_batch = []

    for _, row in df_batch.iterrows():
        check_data = {
            "check_id": str(row.get("check_id", "")),
            "check_title": str(row.get("check_title", "")),
            "check_description": str(row.get("check_description", "")),
            "check_risk": str(row.get("check_risk", "")),
        }

        # Add optional fields if available
        if pd.notna(row.get("check_severity")):
            check_data["check_severity"] = str(row["check_severity"])

        if pd.notna(row.get("check_service")):
            check_data["check_service"] = str(row["check_service"])

        if pd.notna(row.get("attributes_impact_statement")):
            check_data["attributes_impact_statement"] = str(row["attributes_impact_statement"])

        check_batch.append(check_data)

    return check_batch


def check_credentials():
    """Check if AWS credentials are available."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_KEY")

    if not access_key or not secret_key:
        print("⚠️  WARNING: AWS credentials not found in environment variables!")
        print("   Looking for: AWS_ACCESS_KEY_ID or AWS_ACCESS_KEY")
        print("   Looking for: AWS_SECRET_ACCESS_KEY or AWS_SECRET_KEY")
        print("\n   The script will try to use default AWS credential chain.")
        print("   If that fails, please set the environment variables:")
        print("     export AWS_ACCESS_KEY_ID='your-key'")
        print("     export AWS_SECRET_ACCESS_KEY='your-secret'")
        print("     export AWS_REGION='us-east-1'")
        print()
    else:
        print("✓ AWS credentials found in environment variables")
        print()

def process_azure_checks():
    """Main processing function."""
    print("=" * 80)
    print("Azure Check Risk Labeling - MITRE ATT&CK Mapping")
    print("=" * 80)

    # Check credentials
    check_credentials()

    # Load Azure checks
    df = load_azure_checks(AZURE_CSV_PATH)

    all_results = []
    total_batches = (len(df) + BATCH_SIZE - 1) // BATCH_SIZE

    print(f"\nProcessing {len(df)} checks in {total_batches} batches of {BATCH_SIZE}...")
    print("-" * 80)

    for i in range(0, len(df), BATCH_SIZE):
        batch_num = i // BATCH_SIZE + 1
        batch_df = df.iloc[i:i+BATCH_SIZE]

        print(f"\nProcessing batch {batch_num}/{total_batches} (checks {i+1}-{min(i+BATCH_SIZE, len(df))})...")

        # Prepare check batch
        check_batch = prepare_check_batch(batch_df)

        # Build prompt and call Claude
        try:
            payload = build_user_prompt(check_batch)
            result = call_claude(payload)
            batch_results = result.get("results", [])

            if not batch_results:
                print(f"  ⚠️  Warning: No results returned for batch {batch_num}")
                continue

            print(f"  ✅ Received {len(batch_results)} results")
            all_results.extend(batch_results)

            # Save batch results
            batch_file = RESULTS_DIR / f"azure_batch_{batch_num}.json"
            with open(batch_file, "w") as f:
                json.dump(batch_results, f, indent=2)
            print(f"  💾 Saved to {batch_file}")

        except Exception as e:
            print(f"  ❌ Error processing batch {batch_num}: {e}")
            import traceback
            traceback.print_exc()
            continue

    # Save all results
    all_results_file = RESULTS_DIR / "all_azure_results.json"
    with open(all_results_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print("\n" + "=" * 80)
    print("Processing Complete")
    print("=" * 80)
    print(f"Total checks processed: {len(df)}")
    print(f"Total results received: {len(all_results)}")
    print(f"All results saved to: {all_results_file}")
    print("=" * 80)

    return all_results


if __name__ == "__main__":
    try:
        results = process_azure_checks()
        print(f"\n✅ Success! Processed {len(results)} checks.")
        print("\nNext step: Run merge_azure_results.py to combine with original CSV")
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
