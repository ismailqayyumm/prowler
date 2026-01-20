#!/usr/bin/env python3
"""
Merge LLM Risk Labeling Results with Azure CSV

This script merges the LLM-generated MITRE ATT&CK risk labels back into
the original Azure checks CSV file.
"""

import pandas as pd
import json
import sys
from pathlib import Path
from datetime import datetime

# Paths
AZURE_CSV_PATH = "../opensearch_work/data/azure_checks_extracted_20260120_214536.csv"
LLM_RESULTS_PATH = "results/all_azure_results.json"
OUTPUT_CSV_PATH = "../opensearch_work/data/azure_checks_with_llm_risk_labels.csv"


def load_llm_results(json_path):
    """Load LLM results from JSON file."""
    results_file = Path(__file__).parent / json_path

    if not results_file.exists():
        raise FileNotFoundError(f"LLM results file not found: {results_file}")

    with open(results_file, 'r') as f:
        results = json.load(f)

    print(f"Loaded {len(results)} LLM results from {results_file}")
    return results


def load_azure_csv(csv_path):
    """Load Azure checks CSV."""
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
    print(f"Loaded {len(df)} checks from {csv_file}")
    return df, csv_file


def merge_results(df, llm_results):
    """Merge LLM results into DataFrame."""
    # Create a dictionary for quick lookup
    results_dict = {result['check_id']: result for result in llm_results}

    # Initialize new columns
    df['mitre_technique_id'] = None
    df['mitre_tactic'] = None
    df['mitre_technique_name'] = None
    df['risk_main_category'] = None
    df['risk_sub_category'] = None
    df['llm_reasoning'] = None
    df['llm_confidence'] = None

    # Merge results
    matched = 0
    unmatched = []

    for idx, row in df.iterrows():
        check_id = str(row.get('check_id', ''))

        if check_id in results_dict:
            result = results_dict[check_id]
            df.at[idx, 'mitre_technique_id'] = result.get('mitre_technique_id', '')
            df.at[idx, 'mitre_tactic'] = result.get('mitre_tactic', '')
            df.at[idx, 'mitre_technique_name'] = result.get('mitre_technique_name', '')
            df.at[idx, 'risk_main_category'] = result.get('risk_main_category', '')
            df.at[idx, 'risk_sub_category'] = result.get('risk_sub_category', '')
            df.at[idx, 'llm_reasoning'] = result.get('reasoning', '')
            df.at[idx, 'llm_confidence'] = result.get('confidence', None)
            matched += 1
        else:
            unmatched.append(check_id)

    print(f"\nMerge Statistics:")
    print(f"  Matched: {matched}/{len(df)} checks")
    print(f"  Unmatched: {len(unmatched)} checks")

    if unmatched:
        print(f"\n⚠️  Unmatched check IDs (first 10):")
        for check_id in unmatched[:10]:
            print(f"    - {check_id}")
        if len(unmatched) > 10:
            print(f"    ... and {len(unmatched) - 10} more")

    return df


def main():
    """Main function."""
    print("=" * 80)
    print("Merge LLM Risk Labels with Azure CSV")
    print("=" * 80)

    try:
        # Load data
        df, csv_file = load_azure_csv(AZURE_CSV_PATH)
        llm_results = load_llm_results(LLM_RESULTS_PATH)

        # Merge results
        df_merged = merge_results(df, llm_results)

        # Save merged CSV
        output_file = Path(__file__).parent.parent / OUTPUT_CSV_PATH.lstrip("../")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        df_merged.to_csv(output_file, index=False)

        print("\n" + "=" * 80)
        print("Merge Complete")
        print("=" * 80)
        print(f"Output file: {output_file}")
        print(f"Total columns: {len(df_merged.columns)}")
        print(f"Total rows: {len(df_merged)}")

        # Show statistics
        filled = df_merged['mitre_technique_id'].notna().sum()
        print(f"\nLLM Labels Statistics:")
        print(f"  Checks with MITRE labels: {filled}/{len(df_merged)} ({filled/len(df_merged)*100:.1f}%)")

        if filled > 0:
            tactics = df_merged['mitre_tactic'].value_counts()
            print(f"\n  Top MITRE Tactics:")
            for tactic, count in tactics.head(10).items():
                if pd.notna(tactic):
                    print(f"    {tactic}: {count} checks")

        print("=" * 80)
        print(f"\n✅ Success! Final CSV saved to: {output_file}")

    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
