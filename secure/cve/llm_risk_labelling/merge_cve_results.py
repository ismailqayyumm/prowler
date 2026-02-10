#!/usr/bin/env python3
"""
Merge CVE LLM results with original CSV data.
"""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CVE_CSV_PATH = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve" / "azure-resource-data.csv"
RESULTS_DIR = PROJECT_ROOT / "secure" / "cve" / "llm_risk_labelling" / "results"
OUTPUT_DIR = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve"

def find_latest_results() -> Path:
    """Find the most recent LLM results file."""
    result_files = list(RESULTS_DIR.glob("cve_llm_results_*.json"))
    if not result_files:
        raise FileNotFoundError(f"No result files found in {RESULTS_DIR}")

    latest = max(result_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using results file: {latest.name}")
    return latest

def load_llm_results(results_file: Path) -> Dict:
    """Load LLM results from JSON."""
    with open(results_file, 'r', encoding='utf-8') as f:
        results = json.load(f)
    print(f"✓ Loaded {len(results)} CVE analyses")
    return results

def load_mitre_techniques():
    """Load MITRE techniques reference to get technique names."""
    # Load from shared location
    techniques_file = PROJECT_ROOT / "secure" / "shared" / "techniques_extracted_parents_only.json"

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

def merge_data(cve_csv: Path, llm_results: Dict, technique_lookup: Dict) -> Path:
    """Merge LLM results with original CSV data."""
    # Read original CSV
    rows = []
    with open(cve_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        original_fieldnames = reader.fieldnames
        rows = list(reader)

    print(f"✓ Loaded {len(rows)} rows from original CSV")

    # Define new fieldnames
    new_fieldnames = list(original_fieldnames) + [
        'mitre_technique_id',
        'mitre_technique_name',
        'mitre_tactic',
        'risk_main_category',
        'risk_sub_category',
        'risk_confidence',
        'business_impact',
        'finalized_main_category',
        'finalized_sub_category',
        'analysis_timestamp',
        'model_used'
    ]

    # Merge LLM results
    merged_count = 0
    unmatched_count = 0

    for row in rows:
        cve_id = row.get('cve_id', '').strip()

        if cve_id in llm_results:
            result = llm_results[cve_id]

            # MITRE fields
            row['mitre_technique_id'] = result.get('mitre_technique_id', '')
            technique_id = result.get('mitre_technique_id', '')
            row['mitre_technique_name'] = technique_lookup.get(technique_id, result.get('mitre_technique_name', ''))
            row['mitre_tactic'] = result.get('mitre_tactic', '')

            # Risk fields
            row['risk_main_category'] = result.get('risk_main_category', '')
            row['risk_sub_category'] = result.get('risk_sub_category', '')
            row['risk_confidence'] = result.get('risk_confidence', '')
            row['business_impact'] = result.get('business_impact', '')

            # Finalized fields (populated from custom taxonomy)
            row['finalized_main_category'] = result.get('risk_main_category', '')
            row['finalized_sub_category'] = result.get('risk_sub_category', '')

            # Metadata
            row['analysis_timestamp'] = result.get('analysis_timestamp', '')
            row['model_used'] = result.get('model_used', '')

            merged_count += 1
        else:
            # No LLM results for this CVE, leave fields empty
            for field in ['mitre_technique_id', 'mitre_technique_name', 'mitre_tactic',
                         'risk_main_category', 'risk_sub_category', 'risk_confidence',
                         'business_impact', 'finalized_main_category', 'finalized_sub_category',
                         'analysis_timestamp', 'model_used']:
                row[field] = ''
            unmatched_count += 1

    # Write merged CSV
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = OUTPUT_DIR / f"cve_with_llm_risk_labels_{timestamp}.csv"

    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=new_fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✓ Merged data written to {output_file}")
    print(f"  - Total rows: {len(rows)}")
    print(f"  - Rows with LLM data: {merged_count}")
    print(f"  - Rows without LLM data: {unmatched_count}")

    return output_file

def main():
    """Main execution flow."""
    print("="*80)
    print("CVE LLM Results Merger")
    print("="*80)

    # Find latest results
    results_file = find_latest_results()

    # Load LLM results
    llm_results = load_llm_results(results_file)

    # Load MITRE techniques
    technique_lookup = load_mitre_techniques()

    # Merge data
    output_file = merge_data(CVE_CSV_PATH, llm_results, technique_lookup)

    print("\n" + "="*80)
    print(f"✓ Merge complete! Output: {output_file.name}")
    print("="*80)

if __name__ == "__main__":
    main()
