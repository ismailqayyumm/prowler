#!/usr/bin/env python3
"""
KEV CVE LLM Risk Mapper
Queries OpenSearch for CVEs with has_kev=true, then generates MITRE and risk labels
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import time
from opensearchpy import OpenSearch

# Add shared path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'shared'))

try:
    from load_env import load_env_file
    load_env_file()
except ImportError:
    pass

from claude_client import call_claude
from prompts import build_user_prompt

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "secure" / "operations" / "results"
TAXONOMY_PATH = PROJECT_ROOT / "secure" / "shared" / "taxonomy.json"
TECHNIQUES_DB = PROJECT_ROOT / "secure" / "shared" / "techniques_extracted_parents_only.json"

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

def load_techniques_database() -> Dict[str, Dict]:
    """Load MITRE ATT&CK techniques database."""
    with open(TECHNIQUES_DB, 'r', encoding='utf-8') as f:
        data = json.load(f)

    technique_lookup = {}
    for tactic, techniques in data.get('techniques_by_tactic', {}).items():
        for tech in techniques:
            tech_id = tech['technique_id']
            if tech_id not in technique_lookup:
                technique_lookup[tech_id] = {
                    'name': tech['name'],
                    'tactics': [tactic]
                }
            else:
                technique_lookup[tech_id]['tactics'].append(tactic)

    print(f"✓ Loaded {len(technique_lookup)} techniques from database")
    return technique_lookup

def query_kev_cves(client: OpenSearch) -> List[Dict]:
    """Query OpenSearch for CVEs with has_kev=true."""
    print(f"\nQuerying OpenSearch for CVEs with has_kev=true...")

    # Try different possible field paths for has_kev
    query = {
        "query": {
            "bool": {
                "should": [
                    {"term": {"has_kev": True}},
                    {"term": {"cve.has_kev": True}},
                    {"term": {"kev": True}},
                    {"term": {"cve.kev": True}}
                ],
                "minimum_should_match": 1
            }
        },
        "size": 10000  # Adjust if needed
    }

    try:
        response = client.search(index=INDEX_NAME, body=query)
        hits = response['hits']['hits']
        print(f"✓ Found {len(hits)} CVEs with has_kev=true")

        cves = []
        for hit in hits:
            doc = hit['_source']
            cve_data = doc.get('cve', {})
            cve_id = cve_data.get('id', '')

            if cve_id:
                cves.append({
                    'cve_id': cve_id,
                    'description': cve_data.get('description', 'No description available'),
                    'severity': doc.get('cvss', {}).get('severity', 'UNKNOWN'),
                    'score': doc.get('cvss', {}).get('score', 0),
                    'published': cve_data.get('published_date', 'Unknown'),
                    'doc_id': hit['_id']
                })

        return cves
    except Exception as e:
        print(f"❌ Error querying OpenSearch: {e}")
        import traceback
        traceback.print_exc()
        return []

def build_cve_batch_with_context(cves: List[Dict]) -> List[Dict]:
    """Build batch with rich context."""
    checks = []
    for cve in cves:
        desc = cve.get('description', '')
        severity = cve.get('severity', 'UNKNOWN')
        score = cve.get('score', 0)

        # Truncate very long descriptions
        if len(desc) > 500:
            desc = desc[:497] + "..."

        checks.append({
            "check_id": cve['cve_id'],
            "title": f"{cve['cve_id']} - {severity} Severity (CVSS: {score})",
            "description": desc,
            "risk": f"Security vulnerability with {severity} severity rating (KEV - Known Exploited Vulnerability)"
        })
    return checks

def extract_parent_technique(technique_id: str, technique_lookup: Dict) -> tuple:
    """Extract parent technique ID and name, format tactic to Title Case."""
    if not technique_id:
        return '', '', ''

    # Check if it's a sub-technique
    if '.' in technique_id:
        parent_id = technique_id.split('.')[0]
        if parent_id in technique_lookup:
            tech_info = technique_lookup[parent_id]
            tactic = tech_info['tactics'][0] if tech_info['tactics'] else ''
            tactic_title = tactic.replace('-', ' ').title() if tactic else ''
            return parent_id, tech_info['name'], tactic_title
    else:
        # Already a parent technique
        if technique_id in technique_lookup:
            tech_info = technique_lookup[technique_id]
            tactic = tech_info['tactics'][0] if tech_info['tactics'] else ''
            tactic_title = tactic.replace('-', ' ').title() if tactic else ''
            return technique_id, tech_info['name'], tactic_title

    return technique_id, '', ''

def analyze_cve_batch(cves: List[Dict], taxonomy: Dict, technique_lookup: Dict) -> Dict[str, Dict]:
    """Analyze CVEs with context."""
    try:
        checks_batch = build_cve_batch_with_context(cves)

        print(f"\n Analyzing batch of {len(cves)} KEV CVEs...")

        user_prompt = build_user_prompt(taxonomy, checks_batch)
        response_data = call_claude(user_prompt)

        if not response_data or 'results' not in response_data:
            print(f"⚠️  No results")
            return {}

        results = {}
        for i, cve_result in enumerate(response_data['results']):
            if i < len(cves):
                cve = cves[i]
                cve_id = cve['cve_id']

                # Extract MITRE from the 'mitre' array
                mitre_data = cve_result.get('mitre', [])
                if mitre_data and len(mitre_data) > 0:
                    first_mitre = mitre_data[0]
                    mitre_tech_id = first_mitre.get('tech_id', '')
                    mitre_tech_name = first_mitre.get('tech_name', '')
                    mitre_tactic = first_mitre.get('tactic_name', '')

                    # Map to parent technique if needed
                    parent_id, parent_name, parent_tactic = extract_parent_technique(mitre_tech_id, technique_lookup)
                    if parent_id:
                        mitre_tech_id = parent_id
                        if parent_name:
                            mitre_tech_name = parent_name
                        if parent_tactic:
                            mitre_tactic = parent_tactic
                else:
                    mitre_tech_id = ''
                    mitre_tech_name = ''
                    mitre_tactic = ''

                result = {
                    'cve_id': cve_id,
                    'doc_id': cve.get('doc_id', ''),
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
    print("KEV CVE LLM Risk Mapper")
    print("="*80)

    # Load environment
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / '.env')

    # Initialize
    taxonomy = load_taxonomy()
    technique_lookup = load_techniques_database()
    client = get_opensearch_client()

    # Query KEV CVEs
    kev_cves = query_kev_cves(client)

    if not kev_cves:
        print("No KEV CVEs found. Exiting.")
        return

    # Process in batches
    batch_size = 10
    all_results = {}

    for i in range(0, len(kev_cves), batch_size):
        batch = kev_cves[i:i+batch_size]
        print(f"\n[Batch {i//batch_size + 1}] Processing {len(batch)} CVEs...")

        results = analyze_cve_batch(batch, taxonomy, technique_lookup)
        all_results.update(results)

        if i + batch_size < len(kev_cves):
            time.sleep(2)

    # Save
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = RESULTS_DIR / f"kev_cve_llm_results_{timestamp}.json"
    save_results(all_results, output_file)

    print("\n" + "="*80)
    print(f"✓ Completed: {len(all_results)}/{len(kev_cves)} KEV CVEs analyzed")
    print("="*80)

if __name__ == "__main__":
    main()



