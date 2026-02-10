#!/usr/bin/env python3
"""
CVE LLM Risk Mapper
Analyzes CVE vulnerabilities using Claude via AWS Bedrock to generate:
1. MITRE ATT&CK mappings (parent techniques only)
2. Custom taxonomy risk categorization
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

# Load environment variables from .env if available
try:
    from load_env import load_env_file
    load_env_file()
except ImportError:
    pass

from claude_client import call_claude
from prompts import build_user_prompt

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CVE_CSV_PATH = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve" / "azure-resource-data.csv"
RESULTS_DIR = PROJECT_ROOT / "secure" / "cve" / "llm_risk_labelling" / "results"
TAXONOMY_PATH = PROJECT_ROOT / "secure" / "shared" / "taxonomy.json"

# Ensure results directory exists
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def load_taxonomy():
    """Load taxonomy from shared location."""
    taxonomy_path = PROJECT_ROOT / "secure" / "shared" / "taxonomy.json"

    if not taxonomy_path.exists():
        raise FileNotFoundError(f"Taxonomy file not found: {taxonomy_path}")

    with open(taxonomy_path, 'r') as f:
        taxonomy = json.load(f)
    print(f"✓ Loaded taxonomy from {taxonomy_path}")
    return taxonomy

def load_cve_data() -> Dict[str, List[Dict]]:
    """Load CVE data and group by CVE ID."""
    if not CVE_CSV_PATH.exists():
        raise FileNotFoundError(f"CVE CSV not found: {CVE_CSV_PATH}")

    cve_groups = {}
    with open(CVE_CSV_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get('cve_id', '').strip()
            if cve_id and cve_id != 'NA':
                if cve_id not in cve_groups:
                    cve_groups[cve_id] = []
                cve_groups[cve_id].append(row)

    print(f"✓ Loaded {len(cve_groups)} unique CVEs from {len(list(csv.DictReader(open(CVE_CSV_PATH))))} total rows")
    return cve_groups

def build_cve_prompt(cve_id: str, cve_data: List[Dict]) -> str:
    """Build a prompt for CVE analysis."""
    # Get unique context from existing mappings
    existing_techniques = set()
    existing_tactics = set()

    for row in cve_data:
        if row.get('llm_technique_id') and row['llm_technique_id'] != 'NA':
            existing_techniques.add(f"{row['llm_technique_id']} - {row.get('llm_technique', '')}")
        if row.get('llm_tactic') and row['llm_tactic'] != 'NA':
            existing_tactics.add(row['llm_tactic'])

    context = f"""
CVE ID: {cve_id}
Affected Resources: {len(cve_data)} Azure VM instances
Resource Type: Microsoft.Compute/virtualMachines

Existing Context (if available):
- Techniques: {', '.join(existing_techniques) if existing_techniques else 'Not provided'}
- Tactics: {', '.join(existing_tactics) if existing_tactics else 'Not provided'}

Description: This CVE affects Azure virtual machine resources and requires security analysis for proper risk categorization and threat mapping.
"""

    return context.strip()

def analyze_cve(cve_id: str, cve_data: List[Dict], taxonomy: Dict) -> Optional[Dict]:
    """Analyze a CVE using Claude."""
    try:
        cve_context = build_cve_prompt(cve_id, cve_data)

        # Build check batch in the format expected by prompts.py
        checks_batch = [{
            "check_id": cve_id,
            "title": f"CVE Vulnerability: {cve_id}",
            "description": cve_context,
            "risk": "Security vulnerability requiring assessment"
        }]

        print(f"\n{'='*80}")
        print(f"Analyzing: {cve_id}")
        print(f"{'='*80}")

        # Call Claude
        user_prompt = build_user_prompt(taxonomy, checks_batch)
        response_data = call_claude(user_prompt)

        if response_data and 'results' in response_data and len(response_data['results']) > 0:
            # Get the first result from the batch
            cve_result = response_data['results'][0]

            # Transform to our expected format
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

            print(f"✓ Successfully analyzed {cve_id}")
            print(f"  - MITRE: {result['mitre_technique_id']} / {result['mitre_tactic']}")
            print(f"  - Risk: {result['risk_main_category']} > {result['risk_sub_category']}")
            return result
        else:
            print(f"⚠️  No result for {cve_id}")
            return None

    except Exception as e:
        print(f"❌ Error analyzing {cve_id}: {e}")
        import traceback
        traceback.print_exc()
        return None

def save_results(results: Dict[str, Dict], output_file: Path):
    """Save LLM results to JSON file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Saved results to {output_file}")

def main():
    """Main execution flow."""
    print("="*80)
    print("CVE LLM Risk Mapper")
    print("="*80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Load taxonomy
    taxonomy = load_taxonomy()

    # Load CVE data
    cve_groups = load_cve_data()

    # Analyze each unique CVE
    results = {}
    total = len(cve_groups)

    for idx, (cve_id, cve_data) in enumerate(cve_groups.items(), 1):
        print(f"\n[{idx}/{total}] Processing {cve_id}...")

        result = analyze_cve(cve_id, cve_data, taxonomy)
        if result:
            results[cve_id] = result

        # Rate limiting
        if idx < total:
            time.sleep(2)

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = RESULTS_DIR / f"cve_llm_results_{timestamp}.json"
    save_results(results, output_file)

    # Summary
    print("\n" + "="*80)
    print("Summary")
    print("="*80)
    print(f"Total CVEs processed: {total}")
    print(f"Successful analyses: {len(results)}")
    print(f"Failed analyses: {total - len(results)}")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    main()
