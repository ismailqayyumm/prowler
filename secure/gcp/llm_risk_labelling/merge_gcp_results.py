#!/usr/bin/env python3
"""
Merge LLM risk labeling results with GCP checks CSV.

This script:
1. Loads the LLM results from results/all_gcp_results.json
2. Loads the original GCP CSV
3. Loads MITRE technique names from reference file
4. Merges the MITRE ATT&CK predictions and risk labels
5. Adds columns: technique_id, tactic, technique_name (from MITRE reference)
6. Outputs to: opensearch_work/data/gcp/gcp_checks_with_llm_risk_labels.csv
"""

import pandas as pd
import json
import sys
from pathlib import Path


def load_mitre_techniques():
    """Load MITRE techniques reference to get technique names."""
    # Load from shared location
    techniques_file = Path(__file__).parent.parent.parent / "shared" / "techniques_extracted_parents_only.json"
    
    if not techniques_file.exists():
        print(f"⚠️  Warning: MITRE techniques file not found at {techniques_file}")
        return {}
    
    try:
        with open(techniques_file, 'r') as f:
            data = json.load(f)

        # Build a lookup dictionary: technique_id -> technique_name
        technique_lookup = {}
        for tech in data.get('all_techniques', []):
            tech_id = tech.get('technique_id', '')
            tech_name = tech.get('name', '')
            if tech_id and tech_name:
                technique_lookup[tech_id] = tech_name

        print(f"✓ Loaded {len(technique_lookup)} MITRE technique names from reference")
        return technique_lookup

    except Exception as e:
        print(f"⚠️  Warning: Could not load MITRE techniques: {e}")
        return {}


def merge_results(df, llm_results, technique_lookup):
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

    # Additional columns requested by user (simplified names)
    df['technique_id'] = None
    df['tactic'] = None
    df['technique_name'] = None

    # Merge results
    matched = 0
    unmatched = []

    for idx, row in df.iterrows():
        check_id = str(row.get('check_id', ''))

        if check_id in results_dict:
            result = results_dict[check_id]

            # Extract MITRE fields
            mitre_tech_id = result.get('mitre_technique_id', '')
            mitre_tactic = result.get('mitre_tactic', '')
            mitre_tech_name = result.get('mitre_technique_name', '')

            # If technique name not in result, look it up from reference
            if not mitre_tech_name and mitre_tech_id and mitre_tech_id in technique_lookup:
                mitre_tech_name = technique_lookup[mitre_tech_id]
                print(f"  ℹ️  Looked up technique name for {mitre_tech_id}: {mitre_tech_name}")

            # Populate MITRE columns (with prefix)
            df.at[idx, 'mitre_technique_id'] = mitre_tech_id
            df.at[idx, 'mitre_tactic'] = mitre_tactic
            df.at[idx, 'mitre_technique_name'] = mitre_tech_name

            # Populate risk categories
            df.at[idx, 'risk_main_category'] = result.get('risk_main_category', '')
            df.at[idx, 'risk_sub_category'] = result.get('risk_sub_category', '')

            # Populate LLM metadata
            df.at[idx, 'llm_reasoning'] = result.get('llm_reasoning', '')
            df.at[idx, 'llm_confidence'] = result.get('llm_confidence', None)

            # Populate simplified columns (without prefix) - same data
            df.at[idx, 'technique_id'] = mitre_tech_id
            df.at[idx, 'tactic'] = mitre_tactic
            df.at[idx, 'technique_name'] = mitre_tech_name

            # Populate finalized fields with CUSTOM TAXONOMY (not MITRE)
            # finalized.main and finalized.main_category = risk_main_category (custom taxonomy)
            df.at[idx, 'finalized_main'] = result.get('risk_main_category', '')
            df.at[idx, 'finalized_main_category'] = result.get('risk_main_category', '')
            # finalized.sub and finalized.sub_category = risk_sub_category (custom taxonomy)
            df.at[idx, 'finalized_sub'] = result.get('risk_sub_category', '')
            df.at[idx, 'finalized_sub_category'] = result.get('risk_sub_category', '')

            matched += 1
        else:
            unmatched.append(check_id)

    print(f"\n✓ Matched {matched} checks")
    if unmatched:
        print(f"⚠️  {len(unmatched)} checks not found in LLM results")

    return df


def main():
    """Main merge function."""
    print("=" * 80)
    print("Merging LLM Results with GCP Checks CSV")
    print("=" * 80)

    # Load MITRE techniques reference
    technique_lookup = load_mitre_techniques()

    # Load LLM results
    results_file = Path(__file__).parent / "results" / "all_gcp_results.json"
    if not results_file.exists():
        print(f"\n❌ Error: LLM results file not found: {results_file}")
        print("   Run gcp_mapper.py first to generate LLM results.")
        sys.exit(1)

    with open(results_file, 'r') as f:
        llm_results = json.load(f)

    print(f"✓ Loaded {len(llm_results)} LLM results from {results_file.name}")

    # Find GCP CSV
    csv_dir = Path(__file__).parent / "../opensearch_work/data/gcp"
    gcp_files = list(csv_dir.glob("gcp_checks_extracted_*.csv"))

    if not gcp_files:
        print(f"\n❌ Error: No GCP CSV found in {csv_dir}")
        sys.exit(1)

    csv_file = max(gcp_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using GCP CSV: {csv_file.name}")

    # Load CSV
    df = pd.read_csv(csv_file)
    print(f"✓ Loaded {len(df)} checks from CSV")

    # Merge results
    print("\nMerging LLM results with CSV...")
    df = merge_results(df, llm_results, technique_lookup)

    # Save merged results (output to same directory as input CSV)
    output_file = csv_dir / "gcp_checks_with_llm_risk_labels.csv"
    df.to_csv(output_file, index=False)

    print("\n" + "=" * 80)
    print("Merge Complete")
    print("=" * 80)
    print(f"Output file: {output_file}")
    print(f"Total rows: {len(df)}")

    # Show columns summary
    llm_columns = [
        'technique_id', 'tactic', 'technique_name',
        'mitre_technique_id', 'mitre_tactic', 'mitre_technique_name',
        'risk_main_category', 'risk_sub_category',
        'llm_reasoning', 'llm_confidence'
    ]

    print("\nNew columns added:")
    for col in llm_columns:
        if col in df.columns:
            non_null = df[col].notna().sum()
            print(f"  - {col}: {non_null}/{len(df)} populated")

    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
        print("\n✅ Success! Merged CSV ready for upload to OpenSearch.")
        print("\nNext step: Run upload_gcp_checks.py to upload to OpenSearch index")
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
