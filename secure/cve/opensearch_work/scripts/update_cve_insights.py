#!/usr/bin/env python3
"""
Update existing CVE documents in OpenSearch with LLM risk labels.
Only updates llm.* and finalized.* fields based on CVE ID.
"""

import csv
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from opensearchpy import OpenSearch, helpers

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve"
OUTPUT_DIR = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "outputs"

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# OpenSearch configuration from environment
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

    # Test connection
    info = client.info()
    print(f"✓ Connected to OpenSearch: {info['version']['number']}")
    return client

def delete_recent_uploads(client: OpenSearch):
    """Delete recently uploaded documents (created in last 5 minutes)."""
    print("\n" + "="*80)
    print("Cleaning up recently uploaded documents...")
    print("="*80)

    # Delete documents created in the last 5 minutes
    five_minutes_ago = datetime.utcnow().replace(microsecond=0).isoformat().replace('+00:00', '') + 'Z'

    query = {
        "query": {
            "range": {
                "created_at": {
                    "gte": "2026-01-26T13:30:00.000Z"  # Documents created today
                }
            }
        }
    }

    try:
        response = client.delete_by_query(
            index=INDEX_NAME,
            body=query
        )
        deleted = response.get('deleted', 0)
        print(f"✓ Deleted {deleted} recently uploaded documents")
        return deleted
    except Exception as e:
        print(f"⚠️  Error during cleanup: {e}")
        return 0

def find_latest_csv() -> Path:
    """Find the most recent CVE CSV with LLM labels."""
    csv_files = list(DATA_DIR.glob("cve_with_llm_risk_labels_*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No labeled CVE CSV found in {DATA_DIR}")

    latest = max(csv_files, key=lambda p: p.stat().st_mtime)
    print(f"✓ Using CSV file: {latest.name}")
    return latest

def has_value(value: str) -> bool:
    """Check if value is not empty, NA, or None."""
    if not value:
        return False
    value_str = str(value).strip()
    return value_str and value_str.upper() not in ['NA', 'N/A', 'NONE', '']

def build_llm_object(row: Dict) -> Dict:
    """Build the llm object from row data."""
    llm_obj = {}

    # MITRE analysis
    mitre_analysis = {}
    has_mitre_data = False

    if has_value(row.get('mitre_technique_id')):
        mitre_analysis['technique_id'] = str(row['mitre_technique_id']).strip()
        has_mitre_data = True

    if has_value(row.get('mitre_technique_name')):
        mitre_analysis['technique_name'] = str(row['mitre_technique_name']).strip()
        has_mitre_data = True

    if has_value(row.get('mitre_tactic')):
        # Store as single string, not array
        mitre_analysis['tactics'] = str(row['mitre_tactic']).strip()
        has_mitre_data = True

    if has_value(row.get('risk_confidence')):
        try:
            mitre_analysis['confidence'] = int(row['risk_confidence'])
            has_mitre_data = True
        except (ValueError, TypeError):
            pass

    if has_mitre_data:
        llm_obj['mitre_analysis'] = mitre_analysis

    # Risk analysis
    risk_analysis = {}
    has_risk_data = False

    if has_value(row.get('risk_main_category')):
        risk_analysis['main_category'] = str(row['risk_main_category']).strip()
        has_risk_data = True

    if has_value(row.get('risk_sub_category')):
        # Store as single string, not array
        risk_analysis['sub_categories'] = str(row['risk_sub_category']).strip()
        has_risk_data = True

    if has_value(row.get('risk_confidence')):
        try:
            risk_analysis['categorization_confidence'] = int(row['risk_confidence'])
            has_risk_data = True
        except (ValueError, TypeError):
            pass

    if has_value(row.get('business_impact')):
        risk_analysis['business_impact'] = str(row['business_impact']).strip()
        has_risk_data = True

    if has_risk_data:
        llm_obj['risk_analysis'] = risk_analysis

    # Metadata
    if has_value(row.get('model_used')):
        llm_obj['model_used'] = str(row['model_used']).strip()

    if has_value(row.get('analysis_timestamp')):
        llm_obj['analysis_timestamp'] = str(row['analysis_timestamp']).strip()

    return llm_obj if llm_obj else None

def build_finalized_object(row: Dict) -> Dict:
    """Build the finalized object from row data."""
    finalized = {}

    if has_value(row.get('finalized_main_category')):
        finalized['main_category'] = str(row['finalized_main_category']).strip()

    if has_value(row.get('finalized_sub_category')):
        finalized['sub_category'] = str(row['finalized_sub_category']).strip()

    return finalized if finalized else None

def get_unique_cves(csv_file: Path) -> Dict[str, Dict]:
    """Get unique CVE IDs and their LLM data."""
    cve_data = {}

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = str(row.get('cve_id', '')).strip()
            if cve_id and cve_id not in cve_data:
                # Store the first occurrence of each CVE
                llm_obj = build_llm_object(row)
                finalized_obj = build_finalized_object(row)

                cve_data[cve_id] = {
                    'llm': llm_obj,
                    'finalized': finalized_obj
                }

    print(f"✓ Found {len(cve_data)} unique CVEs with LLM data")
    return cve_data

def update_cve_documents(client: OpenSearch, cve_data: Dict[str, Dict]) -> Dict:
    """Update existing CVE documents with LLM data."""
    print(f"\n{'='*80}")
    print(f"Updating CVE documents in index: {INDEX_NAME}")
    print(f"{'='*80}")

    success_count = 0
    error_count = 0
    not_found_count = 0

    current_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    for cve_id, data in cve_data.items():
        try:
            # Search for documents with this CVE ID (using cve.id field)
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

                # Build update body - update nested fields
                update_body = {
                    "doc": {
                        "created_at": current_timestamp,
                        "last_updated_at": current_timestamp
                    }
                }

                # Update impact.llm fields
                if data['llm'] and data['llm'].get('risk_analysis'):
                    risk = data['llm']['risk_analysis']
                    update_body['doc']['impact'] = {
                        "llm": {
                            "main_category": risk.get('main_category', 'NA'),
                            "sub_category": risk.get('sub_categories', 'NA'),  # Note: stored as sub_categories in CSV
                            "reason": risk.get('business_impact', 'NA')
                        }
                    }

                # Update mitre.llm fields
                if data['llm'] and data['llm'].get('mitre_analysis'):
                    mitre = data['llm']['mitre_analysis']
                    if 'mitre' not in update_body['doc']:
                        update_body['doc']['mitre'] = {}
                    update_body['doc']['mitre']['llm'] = {
                        "technique_id": mitre.get('technique_id', 'NA'),
                        "technique": mitre.get('technique_name', 'NA'),
                        "tactic": mitre.get('tactics', 'NA'),  # Note: stored as tactics in CSV
                        "confidence": str(mitre.get('confidence', 'NA')),
                        "reason": data['llm'].get('risk_analysis', {}).get('business_impact', 'NA')
                    }

                # Update impact.finalized fields
                if data['finalized']:
                    if 'impact' not in update_body['doc']:
                        update_body['doc']['impact'] = {}
                    update_body['doc']['impact']['finalized'] = {
                        "main_category": data['finalized'].get('main_category', 'Untriaged'),
                        "sub_category": data['finalized'].get('sub_category', 'Untriaged')
                    }

                # Update document
                client.update(
                    index=INDEX_NAME,
                    id=doc_id,
                    body=update_body
                )
                success_count += 1

            print(f"✓ Updated {len(hits)} document(s) for CVE {cve_id}")

        except Exception as e:
            print(f"❌ Error updating CVE {cve_id}: {e}")
            import traceback
            traceback.print_exc()
            error_count += 1

    return {
        'total_cves': len(cve_data),
        'success': success_count,
        'failed': error_count,
        'not_found': not_found_count
    }

def save_update_log(csv_file: Path, stats: Dict):
    """Save update statistics to log file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = OUTPUT_DIR / f"update_log_{timestamp}.json"

    log_data = {
        'timestamp': datetime.now().isoformat(),
        'source_file': str(csv_file),
        'index_name': INDEX_NAME,
        'opensearch_host': OPENSEARCH_HOST,
        'statistics': stats
    }

    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(log_data, f, indent=2)

    print(f"\n✓ Update log saved to {log_file}")

def main():
    """Main execution flow."""
    print("="*80)
    print("CVE OpenSearch Updater (LLM Risk Labels)")
    print("="*80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Load environment variables
    from dotenv import load_dotenv
    env_path = PROJECT_ROOT / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        print(f"✓ Loaded environment from {env_path}")

    # Connect to OpenSearch
    client = get_opensearch_client()

    # Clean up recently uploaded documents
    deleted = delete_recent_uploads(client)

    # Find latest CSV
    csv_file = find_latest_csv()

    # Get unique CVE data
    cve_data = get_unique_cves(csv_file)

    # Update documents
    stats = update_cve_documents(client, cve_data)

    # Save log
    save_update_log(csv_file, stats)

    print("\n" + "="*80)
    print("Update Summary")
    print("="*80)
    print(f"Index: {INDEX_NAME}")
    print(f"Deleted (cleanup): {deleted}")
    print(f"Total unique CVEs: {stats['total_cves']}")
    print(f"Documents updated: {stats['success']}")
    print(f"Failed: {stats['failed']}")
    print(f"CVEs not found in index: {stats['not_found']}")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    main()
