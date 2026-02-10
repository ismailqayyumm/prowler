#!/usr/bin/env python3
"""
Upload KEV CVE LLM labels to OpenSearch
Updates existing CVE documents with has_kev=true
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from opensearchpy import OpenSearch, helpers

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "secure" / "operations" / "results"
OUTPUT_DIR = PROJECT_ROOT / "secure" / "operations" / "outputs"

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

def load_llm_results() -> Dict:
    """Load latest KEV CVE LLM results."""
    result_files = list(RESULTS_DIR.glob("kev_cve_llm_results_*.json"))
    if not result_files:
        raise FileNotFoundError(f"No KEV CVE results found in {RESULTS_DIR}")

    latest = max(result_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using results: {latest.name}")

    with open(latest, 'r') as f:
        return json.load(f)

def fetch_cve_doc_ids(client: OpenSearch, cve_ids: List[str]) -> Dict[str, List[str]]:
    """Fetch document IDs for all CVEs in bulk."""
    print(f"\nFetching document IDs for {len(cve_ids)} CVEs...")
    cve_to_doc_ids = {}

    # Process in batches to avoid query size limits
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i+batch_size]

        query = {
            "query": {
                "terms": {
                    "cve.id": batch
                }
            },
            "_source": ["cve.id"],
            "size": 10000
        }

        try:
            response = client.search(index=INDEX_NAME, body=query, scroll='2m')
            hits = response['hits']['hits']

            # Handle scroll if needed
            scroll_id = response.get('_scroll_id')
            while len(hits) < response['hits']['total']['value'] and scroll_id:
                scroll_response = client.scroll(scroll_id=scroll_id, scroll='2m')
                hits.extend(scroll_response['hits']['hits'])
                scroll_id = scroll_response.get('_scroll_id')
                if not scroll_response['hits']['hits']:
                    break

            # Map CVE IDs to document IDs
            for hit in hits:
                cve_id = hit['_source'].get('cve', {}).get('id', '')
                if cve_id:
                    if cve_id not in cve_to_doc_ids:
                        cve_to_doc_ids[cve_id] = []
                    cve_to_doc_ids[cve_id].append(hit['_id'])

            if scroll_id:
                client.clear_scroll(scroll_id=scroll_id)

        except Exception as e:
            print(f"⚠️  Error fetching batch {i//batch_size + 1}: {e}")

    print(f"✓ Found document IDs for {len(cve_to_doc_ids)} CVEs")
    return cve_to_doc_ids

def generate_bulk_updates(cve_to_doc_ids: Dict[str, List[str]], llm_results: Dict) -> List[Dict]:
    """Generate bulk update actions."""
    current_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    actions = []

    for cve_id, doc_ids in cve_to_doc_ids.items():
        if cve_id not in llm_results:
            continue

        llm_data = llm_results[cve_id]

        # Build update document
        update_doc = {
            "created_at": current_timestamp,
            "last_updated_at": current_timestamp
        }

        # Add MITRE data
        tech_id = llm_data.get('mitre_technique_id', '').strip()
        if tech_id and tech_id != 'NA':
            update_doc['mitre'] = {
                "llm": {
                    "technique_id": tech_id,
                    "technique": llm_data.get('mitre_technique_name', 'NA'),
                    "tactic": llm_data.get('mitre_tactic', 'NA'),
                    "confidence": str(llm_data.get('risk_confidence', 85)),
                    "reason": llm_data.get('business_impact', 'NA')
                }
            }

        # Add risk data
        update_doc['impact'] = {
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

        # Create update action for each document ID
        for doc_id in doc_ids:
            actions.append({
                "_op_type": "update",
                "_index": INDEX_NAME,
                "_id": doc_id,
                "doc": update_doc
            })

    return actions

def update_cve_documents(client: OpenSearch, llm_results: Dict) -> Dict:
    """Update CVE documents in OpenSearch using bulk operations."""
    print(f"\n{'='*80}")
    print(f"Updating KEV CVE documents in index: {INDEX_NAME}")
    print(f"{'='*80}")

    # Fetch all document IDs
    cve_ids = list(llm_results.keys())
    cve_to_doc_ids = fetch_cve_doc_ids(client, cve_ids)

    # Generate bulk update actions
    print(f"\nGenerating bulk update actions...")
    actions = generate_bulk_updates(cve_to_doc_ids, llm_results)
    print(f"✓ Generated {len(actions)} update actions")

    # Execute bulk updates
    print(f"\nExecuting bulk updates...")
    success_count = 0
    error_count = 0
    not_found_count = len(cve_ids) - len(cve_to_doc_ids)
    updated_cve_ids = []

    try:
        # Use helpers.bulk for efficient bulk operations
        success_count, errors = helpers.bulk(client, actions, chunk_size=500, request_timeout=60)
        error_count = len(errors) if errors else 0

        if errors:
            print(f"⚠️  {len(errors)} errors occurred during bulk update")
            # Print first few errors
            for error in errors[:5]:
                print(f"  - {error}")

        updated_cve_ids = list(cve_to_doc_ids.keys())
        print(f"✓ Bulk update completed: {success_count} successful, {error_count} errors")

    except Exception as e:
        print(f"❌ Error during bulk update: {e}")
        import traceback
        traceback.print_exc()
        error_count = len(actions)

    return {
        'total_cves': len(llm_results),
        'success': success_count,
        'failed': error_count,
        'not_found': not_found_count,
        'updated_cve_ids': updated_cve_ids
    }

def save_log(stats: Dict):
    """Save update log."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = OUTPUT_DIR / f"kev_cve_update_log_{timestamp}.json"

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
    print("KEV CVE OpenSearch Updater")
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
    llm_results = load_llm_results()

    # Update documents
    stats = update_cve_documents(client, llm_results)

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
    print(f"CVEs processed: {len(stats['updated_cve_ids'])}")
    if len(stats['updated_cve_ids']) <= 20:
        print(f"\nUpdated CVE IDs:")
        for cve_id in stats['updated_cve_ids']:
            print(f"  - {cve_id}")
    else:
        print(f"\nSample CVE IDs (first 10):")
        for cve_id in stats['updated_cve_ids'][:10]:
            print(f"  - {cve_id}")
    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    main()
