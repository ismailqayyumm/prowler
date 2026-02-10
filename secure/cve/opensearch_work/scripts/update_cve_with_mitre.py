#!/usr/bin/env python3
"""
Update CVE documents in OpenSearch with MITRE and risk data.
Uses existing MITRE data from CSV + LLM-generated risk categories.
"""

import csv
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict
from opensearchpy import OpenSearch

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve"
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

def load_mitre_data() -> Dict[str, Dict]:
    """Load MITRE data from extracted CSV."""
    csv_files = list(DATA_DIR.glob("cve_extracted_*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No extracted CVE CSV found in {DATA_DIR}")

    latest = max(csv_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using MITRE data from: {latest.name}")

    mitre_data = {}
    with open(latest, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row['cve_id']
            mitre_data[cve_id] = {
                'technique_id': row['mitre_technique_id'],
                'technique': row['mitre_technique_name'],
                'tactic': row['mitre_tactic']
            }

    print(f"✓ Loaded MITRE data for {len(mitre_data)} CVEs")
    return mitre_data

def load_risk_data() -> Dict[str, Dict]:
    """Load risk data from LLM results."""
    results_dir = PROJECT_ROOT / "secure" / "cve" / "llm_risk_labelling" / "results"
    result_files = list(results_dir.glob("cve_llm_results_*.json"))
    if not result_files:
        raise FileNotFoundError(f"No LLM results found in {results_dir}")

    latest = max(result_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using risk data from: {latest.name}")

    with open(latest, 'r', encoding='utf-8') as f:
        risk_data = json.load(f)

    print(f"✓ Loaded risk data for {len(risk_data)} CVEs")
    return risk_data

def update_cve_documents(client: OpenSearch, mitre_data: Dict, risk_data: Dict) -> Dict:
    """Update CVE documents with MITRE and risk data."""
    print(f"\n{'='*80}")
    print(f"Updating CVE documents in index: {INDEX_NAME}")
    print(f"{'='*80}")

    success_count = 0
    error_count = 0
    not_found_count = 0

    current_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Combine all CVE IDs
    all_cve_ids = set(mitre_data.keys()) | set(risk_data.keys())

    for cve_id in all_cve_ids:
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
                print(f"⚠️  CVE {cve_id} not found in index")
                not_found_count += 1
                continue

            # Update all documents with this CVE ID
            for hit in hits:
                doc_id = hit['_id']

                # Build update body
                update_body = {
                    "doc": {
                        "created_at": current_timestamp,
                        "last_updated_at": current_timestamp
                    }
                }

                # Add MITRE data
                mitre_info = mitre_data.get(cve_id, {})
                if mitre_info and mitre_info.get('technique_id'):
                    update_body['doc']['mitre'] = {
                        "llm": {
                            "technique_id": mitre_info['technique_id'],
                            "technique": mitre_info['technique'],
                            "tactic": mitre_info['tactic'],
                            "confidence": "85",
                            "reason": risk_data.get(cve_id, {}).get('business_impact', 'NA')
                        }
                    }

                # Add risk data
                risk_info = risk_data.get(cve_id, {})
                if risk_info:
                    update_body['doc']['impact'] = {
                        "llm": {
                            "main_category": risk_info.get('risk_main_category', 'NA'),
                            "sub_category": risk_info.get('risk_sub_category', 'NA'),
                            "reason": risk_info.get('business_impact', 'NA')
                        },
                        "finalized": {
                            "main_category": risk_info.get('risk_main_category', 'Untriaged'),
                            "sub_category": risk_info.get('risk_sub_category', 'Untriaged')
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
            import traceback
            traceback.print_exc()
            error_count += 1

    return {
        'total_cves': len(all_cve_ids),
        'success': success_count,
        'failed': error_count,
        'not_found': not_found_count
    }

def save_log(stats: Dict):
    """Save update log."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = OUTPUT_DIR / f"cve_update_log_{timestamp}.json"

    log_data = {
        'timestamp': datetime.now().isoformat(),
        'index_name': INDEX_NAME,
        'opensearch_host': OPENSEARCH_HOST,
        'statistics': stats
    }

    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(log_data, f, indent=2)

    print(f"\n✓ Log saved to {log_file}")

def main():
    """Main execution."""
    print("="*80)
    print("CVE OpenSearch Updater (MITRE + Risk)")
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
    mitre_data = load_mitre_data()
    risk_data = load_risk_data()

    # Update documents
    stats = update_cve_documents(client, mitre_data, risk_data)

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
