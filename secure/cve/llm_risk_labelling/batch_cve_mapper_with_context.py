#!/usr/bin/env python3
"""
CVE LLM Risk Mapper with OpenSearch Context
Fetches CVE descriptions from OpenSearch, then generates MITRE and risk labels
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import time
from opensearchpy import OpenSearch

# Add shared path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'shared'))

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

# OpenSearch
OPENSEARCH_HOST = os.getenv('OPENSEARCH_HOST', 'localhost')
OPENSEARCH_PORT = int(os.getenv('OPENSEARCH_PORT', 9200))
OPENSEARCH_USER = os.getenv('OPENSEARCH_USER', 'admin')
OPENSEARCH_PASSWORD = os.getenv('OPENSEARCH_PASSWORD', 'admin')
INDEX_NAME = 'cve-insights'

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def get_opensearch_client() -> OpenSearch:
    """Create OpenSearch client."""
    return OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

def load_taxonomy():
    """Load taxonomy."""
    with open(TAXONOMY_PATH, 'r') as f:
        taxonomy = json.load(f)
    print(f"✓ Loaded taxonomy")
    return taxonomy

def load_cve_ids() -> List[str]:
    """Load CVE IDs."""
    cve_ids = []
    with open(CVE_CSV_PATH, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get('cve_id', '').strip().upper()
            if cve_id and cve_id not in cve_ids:
                cve_ids.append(cve_id)
    print(f"✓ Loaded {len(cve_ids)} CVE IDs")
    return cve_ids

def fetch_cve_context(client: OpenSearch, cve_ids: List[str]) -> Dict[str, Dict]:
    """Fetch CVE descriptions and context from OpenSearch."""
    print(f"\nFetching CVE context from OpenSearch...")
    cve_context = {}

    for cve_id in cve_ids:
        try:
            search_query = {"query": {"term": {"cve.id": cve_id}}}
            response = client.search(index=INDEX_NAME, body=search_query)

            if response['hits']['hits']:
                doc = response['hits']['hits'][0]['_source']
                cve_data = doc.get('cve', {})

                cve_context[cve_id] = {
                    'description': cve_data.get('description', 'No description available'),
                    'severity': doc.get('cvss', {}).get('severity', 'UNKNOWN'),
                    'score': doc.get('cvss', {}).get('score', 0),
                    'published': cve_data.get('published_date', 'Unknown')
                }
                print(f"  ✓ {cve_id}: {cve_context[cve_id]['severity']}")
            else:
                print(f"  ⚠️  {cve_id}: Not found in index")
                cve_context[cve_id] = {
                    'description': f'CVE {cve_id} - Security vulnerability requiring assessment',
                    'severity': 'UNKNOWN',
                    'score': 0,
                    'published': 'Unknown'
                }
        except Exception as e:
            print(f"  ❌ {cve_id}: Error fetching - {e}")
            cve_context[cve_id] = {
                'description': f'CVE {cve_id} - Security vulnerability requiring assessment',
                'severity': 'UNKNOWN',
                'score': 0,
                'published': 'Unknown'
            }

    return cve_context

def build_cve_batch_with_context(cve_ids: List[str], cve_context: Dict) -> List[Dict]:
    """Build batch with rich context."""
    checks = []
    for cve_id in cve_ids:
        context = cve_context.get(cve_id, {})
        desc = context.get('description', '')
        severity = context.get('severity', 'UNKNOWN')
        score = context.get('score', 0)

        # Truncate very long descriptions
        if len(desc) > 500:
            desc = desc[:497] + "..."

        checks.append({
            "check_id": cve_id,
            "title": f"{cve_id} - {severity} Severity (CVSS: {score})",
            "description": desc,
            "risk": f"Security vulnerability with {severity} severity rating"
        })
    return checks

def analyze_cve_batch(cve_ids: List[str], cve_context: Dict, taxonomy: Dict) -> Dict[str, Dict]:
    """Analyze CVEs with context."""
    try:
        checks_batch = build_cve_batch_with_context(cve_ids, cve_context)

        print(f"\n Analyzing batch of {len(cve_ids)} CVEs with full context...")

        user_prompt = build_user_prompt(taxonomy, checks_batch)
        response_data = call_claude(user_prompt)

        if not response_data or 'results' not in response_data:
            print(f"⚠️  No results")
            return {}

        results = {}
        for i, cve_result in enumerate(response_data['results']):
            if i < len(cve_ids):
                cve_id = cve_ids[i]

                # Extract MITRE from the 'mitre' array
                mitre_data = cve_result.get('mitre', [])
                if mitre_data and len(mitre_data) > 0:
                    first_mitre = mitre_data[0]
                    mitre_tech_id = first_mitre.get('tech_id', '')
                    mitre_tech_name = first_mitre.get('tech_name', '')
                    mitre_tactic = first_mitre.get('tactic_name', '')
                else:
                    mitre_tech_id = ''
                    mitre_tech_name = ''
                    mitre_tactic = ''

                result = {
                    'cve_id': cve_id,
                    'mitre_technique_id': mitre_tech_id,
                    'mitre_technique_name': mitre_tech_name,
                    'mitre_tactic': mitre_tactic,
                    'risk_main_category': cve_result.get('impact_main_category', ''),
                    'risk_sub_category': cve_result.get('impact_sub_category', ''),
                    'risk_confidence': int(float(cve_result.get('confidence', 0)) * 100),
                    'business_impact': cve_result.get('chain_interpretation', ''),
                    'model_used': os.getenv('BEDROCK_MODEL_ID', 'claude'),
                    'analysis_timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                results[cve_id] = result
                mitre = f"{result['mitre_technique_id']}" if result['mitre_technique_id'] else "No MITRE"
                print(f"  ✓ {cve_id}: {mitre} | {result['risk_main_category']}")

        return results

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return {}

def save_results(results: Dict, output_file: Path):
    """Save results."""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Saved to {output_file.name}")

def main():
    """Main execution."""
    print("="*80)
    print("CVE LLM Risk Mapper (with OpenSearch Context)")
    print("="*80)

    # Load environment
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / '.env')

    # Initialize
    taxonomy = load_taxonomy()
    cve_ids = load_cve_ids()
    client = get_opensearch_client()

    # Fetch context
    cve_context = fetch_cve_context(client, cve_ids)

    # Process in batches
    batch_size = 10
    all_results = {}

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i+batch_size]
        print(f"\n[Batch {i//batch_size + 1}] Processing {len(batch)} CVEs...")

        results = analyze_cve_batch(batch, cve_context, taxonomy)
        all_results.update(results)

        if i + batch_size < len(cve_ids):
            time.sleep(2)

    # Save
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = RESULTS_DIR / f"cve_with_context_{timestamp}.json"
    save_results(all_results, output_file)

    print("\n" + "="*80)
    print(f"✓ Completed: {len(all_results)}/{len(cve_ids)} CVEs analyzed")
    print("="*80)

if __name__ == "__main__":
    main()
