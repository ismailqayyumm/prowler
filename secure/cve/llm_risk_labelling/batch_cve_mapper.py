#!/usr/bin/env python3
"""
CVE LLM Risk Mapper - Batch version for CVE IDs only
Generates both MITRE and risk labels from CVE IDs
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import time

# Add shared path to import shared modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'shared'))

# Load environment variables
try:
    from load_env import load_env_file
    load_env_file()
except ImportError:
    pass

from claude_client import call_claude
from prompts import build_user_prompt

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CVE_CSV_PATH = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve" / "new_cves_to_label.csv"
RESULTS_DIR = PROJECT_ROOT / "secure" / "cve" / "llm_risk_labelling" / "results"
TAXONOMY_PATH = PROJECT_ROOT / "secure" / "shared" / "taxonomy.json"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def load_taxonomy():
    """Load taxonomy from shared location."""
    if not TAXONOMY_PATH.exists():
        raise FileNotFoundError(f"Taxonomy file not found: {TAXONOMY_PATH}")

    with open(TAXONOMY_PATH, 'r') as f:
        taxonomy = json.load(f)
    print(f"✓ Loaded taxonomy from {TAXONOMY_PATH}")
    return taxonomy

def load_cve_ids() -> List[str]:
    """Load CVE IDs from CSV."""
    if not CVE_CSV_PATH.exists():
        raise FileNotFoundError(f"CVE CSV not found: {CVE_CSV_PATH}")

    cve_ids = []
    with open(CVE_CSV_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get('cve_id', '').strip().upper()
            if cve_id and cve_id not in cve_ids:
                cve_ids.append(cve_id)

    print(f"✓ Loaded {len(cve_ids)} unique CVEs")
    return cve_ids

def build_cve_batch(cve_ids: List[str]) -> List[Dict]:
    """Build a batch of CVEs for LLM analysis."""
    checks = []
    for cve_id in cve_ids:
        checks.append({
            "check_id": cve_id,
            "title": f"Security Vulnerability: {cve_id}",
            "description": f"This CVE ({cve_id}) represents a security vulnerability that needs risk assessment and MITRE ATT&CK classification.",
            "risk": "Security vulnerability requiring assessment"
        })
    return checks

def analyze_cve_batch(cve_ids: List[str], taxonomy: Dict) -> Dict[str, Dict]:
    """Analyze a batch of CVEs using Claude."""
    try:
        checks_batch = build_cve_batch(cve_ids)

        print(f"\nAnalyzing batch of {len(cve_ids)} CVEs...")

        # Call Claude
        user_prompt = build_user_prompt(taxonomy, checks_batch)
        response_data = call_claude(user_prompt)

        if not response_data or 'results' not in response_data:
            print(f"⚠️  No results returned")
            return {}

        # Map results back to CVE IDs
        results = {}
        for i, cve_result in enumerate(response_data['results']):
            if i < len(cve_ids):
                cve_id = cve_ids[i]
                result = {
                    'cve_id': cve_id,
                    'mitre_technique_id': cve_result.get('mitre_technique_id', ''),
                    'mitre_technique_name': cve_result.get('mitre_technique_name', ''),
                    'mitre_tactic': cve_result.get('mitre_tactic', ''),
                    'risk_main_category': cve_result.get('impact_main_category', ''),
                    'risk_sub_category': cve_result.get('impact_sub_category', ''),
                    'risk_confidence': int(float(cve_result.get('confidence', 0)) * 100),
                    'business_impact': cve_result.get('chain_interpretation', ''),
                    'model_used': os.getenv('BEDROCK_MODEL_ID', 'claude'),
                    'analysis_timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                results[cve_id] = result
                print(f"✓ {cve_id}: {result['risk_main_category']} > {result['risk_sub_category']}")

        return results

    except Exception as e:
        print(f"❌ Error analyzing batch: {e}")
        import traceback
        traceback.print_exc()
        return {}

def save_results(results: Dict[str, Dict], output_file: Path):
    """Save LLM results to JSON file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Saved results to {output_file}")

def main():
    """Main execution flow."""
    print("="*80)
    print("CVE Batch LLM Risk Mapper")
    print("="*80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Load taxonomy
    taxonomy = load_taxonomy()

    # Load CVE IDs
    cve_ids = load_cve_ids()

    # Process in batches of 10
    batch_size = 10
    all_results = {}

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i+batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (len(cve_ids) + batch_size - 1) // batch_size

        print(f"\n[Batch {batch_num}/{total_batches}] Processing {len(batch)} CVEs...")

        results = analyze_cve_batch(batch, taxonomy)
        all_results.update(results)

        # Rate limiting between batches
        if i + batch_size < len(cve_ids):
            time.sleep(2)

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = RESULTS_DIR / f"new_cve_llm_results_{timestamp}.json"
    save_results(all_results, output_file)

    # Summary
    print("\n" + "="*80)
    print("Summary")
    print("="*80)
    print(f"Total CVEs processed: {len(cve_ids)}")
    print(f"Successful analyses: {len(all_results)}")
    print(f"Failed analyses: {len(cve_ids) - len(all_results)}")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    main()
