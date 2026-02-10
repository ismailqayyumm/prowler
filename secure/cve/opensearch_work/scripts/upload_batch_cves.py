#!/usr/bin/env python3
"""
Upload new CVE labels to OpenSearch (without pre-existing MITRE data)
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict
from opensearchpy import OpenSearch

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "secure" / "cve" / "llm_risk_labelling" / "results"
TECHNIQUES_DB = PROJECT_ROOT / "secure" / "shared" / "techniques_extracted_parents_only.json"
OUTPUT_DIR = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "outputs"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# OpenSearch configuration
OPENSEARCH_HOST = os.getenv('OPENSEARCH_HOST', 'localhost')
OPENSEARCH_PORT = int(os.getenv('OPENSEARCH_PORT', 9200))
OPENSEARCH_USER = os.getenv('OPENSEARCH_USER', 'admin')
OPENSEARCH_PASSWORD = os.getenv('OPENSEARCH_PASSWORD', 'admin')
INDEX_NAME = 'cve-insights'

def get_opensearch_client() -> OpenSearch:
    """Create OpenSearch client."""
    client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    info = client.info()
    print(f"✓ Connected to OpenSearch: {info['version']['number']}")
    return client

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

def extract_parent_technique_id(technique_id: str) -> str:
    """Extract parent technique ID from sub-technique."""
    if '.' in technique_id:
        return technique_id.split('.')[0]
    return technique_id

def format_tactic_title_case(tactic: str) -> str:
    """Convert tactic to Title Case."""
    if not tactic:
        return ''
    return tactic.replace('-', ' ').title()

def load_llm_results() -> Dict:
    """Load latest LLM results."""
    result_files = list(RESULTS_DIR.glob("cve_with_context_*.json"))
    if not result_files:
        # Fallback to old format
        result_files = list(RESULTS_DIR.glob("new_cve_llm_results_*.json"))
    if not result_files:
        raise FileNotFoundError(f"No results found in {RESULTS_DIR}")

    latest = max(result_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using results: {latest.name}")

    with open(latest, 'r') as f:
        return json.load(f)

def update_cve_documents(client: OpenSearch, llm_results: Dict, technique_lookup: Dict) -> Dict:
    """Update CVE documents in OpenSearch."""
    print(f"\n{'='*80}")
    print(f"Updating CVE documents in index: {INDEX_NAME}")
    print(f"{'='*80}")

    success_count = 0
    error_count = 0
    not_found_count = 0

    current_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    for cve_id, llm_data in llm_results.items():
        try:
            # Search for document
            search_query = {
                "query": {
                    "term": {
                        "cve.id": cve_id
                    }
                }
            }

            response = client.search(index=INDEX_NAME, body=search_query)
            hits = response['hits']['hits']

            if not hits:
                print(f"⚠️  {cve_id} not found in index")
                not_found_count += 1
                continue

            # Update document
            for hit in hits:
                doc_id = hit['_id']

                update_body = {
                    "doc": {
                        "created_at": current_timestamp,
                        "last_updated_at": current_timestamp
                    }
                }

                # Process MITRE data
                tech_id = llm_data.get('mitre_technique_id', '').strip()
                if tech_id and tech_id != 'NA':
                    # Use parent technique
                    parent_tech_id = extract_parent_technique_id(tech_id)
                    tech_info = technique_lookup.get(parent_tech_id)

                    if tech_info:
                        primary_tactic = format_tactic_title_case(tech_info['tactics'][0]) if tech_info['tactics'] else ''
                        update_body['doc']['mitre'] = {
                            "llm": {
                                "technique_id": parent_tech_id,
                                "technique": tech_info['name'],
                                "tactic": primary_tactic,
                                "confidence": str(llm_data.get('risk_confidence', 85)),
                                "reason": llm_data.get('business_impact', 'NA')
                            }
                        }

                # Add risk data
                update_body['doc']['impact'] = {
                    "llm": {
                        "main_category": llm_data.get('risk_main_category', 'NA'),
                        "sub_category": llm_data.get('risk_sub_category', 'NA'),
                        "reason": llm_data.get('business_impact', 'NA')
                    },
                    "finalized": {
                        "main_category": llm_data.get('risk_main_category', 'Untriaged'),
                        "sub_category": llm_data.get('risk_sub_category', 'Untriaged')
                    }
                }

                # Update document
                client.update(
                    index=INDEX_NAME,
                    id=doc_id,
                    body=update_body
                )
                success_count += 1

            print(f"✓ Updated {len(hits)} document(s) for {cve_id}")

        except Exception as e:
            print(f"❌ Error updating {cve_id}: {e}")
            error_count += 1

    return {
        'total_cves': len(llm_results),
        'success': success_count,
        'failed': error_count,
        'not_found': not_found_count
    }

def save_log(stats: Dict):
    """Save update log."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = OUTPUT_DIR / f"batch_cve_update_log_{timestamp}.json"

    log_data = {
        'timestamp': datetime.now().isoformat(),
        'index_name': INDEX_NAME,
        'opensearch_host': OPENSEARCH_HOST,
        'statistics': stats
    }

    with open(log_file, 'w') as f:
        json.dump(log_data, f, indent=2)

    print(f"\n✓ Log saved to {log_file}")

def main():
    """Main execution."""
    print("="*80)
    print("Batch CVE OpenSearch Updater")
    print("="*80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Load environment
    from dotenv import load_dotenv
    env_path = PROJECT_ROOT / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        print(f"✓ Loaded environment from {env_path}")

    # Connect to OpenSearch
    client = get_opensearch_client()

    # Load data
    technique_lookup = load_techniques_database()
    llm_results = load_llm_results()

    # Update documents
    stats = update_cve_documents(client, llm_results, technique_lookup)

    # Save log
    save_log(stats)

    print("\n" + "="*80)
    print("Update Summary")
    print("="*80)
    print(f"Index: {INDEX_NAME}")
    print(f"Total CVEs: {stats['total_cves']}")
    print(f"Documents updated: {stats['success']}")
    print(f"Failed: {stats['failed']}")
    print(f"Not found: {stats['not_found']}")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    main()
