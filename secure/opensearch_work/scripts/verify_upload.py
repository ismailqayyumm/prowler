#!/usr/bin/env python3
"""
Verify Azure Checks Upload to OpenSearch

This script checks if Azure checks were successfully uploaded to OpenSearch.
"""

import os
import sys
from pathlib import Path

# Get script directory and set up paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent

# Load environment variables from .env file if it exists
ENV_FILE = PROJECT_ROOT / '.env'
if ENV_FILE.exists():
    with open(ENV_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key not in os.environ:
                    os.environ[key] = value

try:
    from opensearchpy import OpenSearch
except ImportError:
    print("Error: opensearch-py not installed. Install with: pip install opensearch-py")
    sys.exit(1)

# OpenSearch configuration
host = os.getenv('OPENSEARCH_HOST', 'localhost')
port = int(os.getenv('OPENSEARCH_PORT', '9200'))
username = os.getenv('OPENSEARCH_USERNAME') or os.getenv('OPENSEARCH_USER')
password = os.getenv('OPENSEARCH_PASSWORD')
index_name = 'prowler-checks-benchmarks'

# Auto-detect SSL
use_ssl = port == 443 or os.getenv('OPENSEARCH_USE_SSL', '').lower() == 'true'
verify_certs = os.getenv('OPENSEARCH_VERIFY_CERTS', 'true').lower() == 'true'

print("=" * 80)
print("Verifying Azure Checks Upload to OpenSearch")
print("=" * 80)
print(f"Host: {host}:{port}")
print(f"Index: {index_name}")
print(f"SSL: {use_ssl}")
print("=" * 80)

# Connect to OpenSearch
try:
    connection_params = {
        'hosts': [{'host': host, 'port': port}],
        'use_ssl': use_ssl,
        'verify_certs': verify_certs,
        'ssl_assert_hostname': False,
        'ssl_show_warn': False,
    }

    if username and password:
        connection_params['http_auth'] = (username, password)

    client = OpenSearch(**connection_params)

    # Test connection
    info = client.info()
    print(f"✓ Connected to OpenSearch: {info['version']['number']}")
    print()

    # Check if index exists
    if not client.indices.exists(index=index_name):
        print(f"❌ Index '{index_name}' does not exist!")
        print("\nAvailable indices:")
        indices = client.indices.get_alias()
        for idx in list(indices.keys())[:10]:
            print(f"  - {idx}")
        sys.exit(1)

    print(f"✓ Index '{index_name}' exists")

    # Get index stats
    stats = client.indices.stats(index=index_name)
    index_stats = stats['indices'][index_name]
    total_docs = index_stats['total']['docs']['count']
    total_size = index_stats['total']['store']['size_in_bytes']

    print(f"✓ Total documents in index: {total_docs}")
    print(f"✓ Index size: {total_size / 1024 / 1024:.2f} MB")
    print()

    # Search for Azure documents
    print("Searching for Azure checks...")
    azure_query = {
        "query": {
            "term": {
                "provider": "azure"
            }
        },
        "size": 0
    }

    result = client.search(index=index_name, body=azure_query)
    azure_count = result['hits']['total']['value']

    print(f"✓ Azure documents found: {azure_count}")
    print()

    # Get sample Azure documents
    if azure_count > 0:
        sample_query = {
            "query": {
                "term": {
                    "provider": "azure"
                }
            },
            "size": 5,
            "sort": [{"created_at": {"order": "desc"}}]
        }

        result = client.search(index=index_name, body=sample_query)
        print("Sample Azure documents (most recent):")
        print("-" * 80)
        for hit in result['hits']['hits']:
            doc = hit['_source']
            print(f"  ID: {hit['_id']}")
            print(f"  Title: {doc.get('check', {}).get('title', 'N/A')[:60]}...")
            print(f"  Provider: {doc.get('provider', 'N/A')}")
            print(f"  Created: {doc.get('created_at', 'N/A')}")
            if 'llm' in doc:
                llm = doc['llm']
                if 'mitre_analysis' in llm:
                    print(f"  MITRE: {llm['mitre_analysis'].get('technique_id', 'N/A')}")
                if 'risk_analysis' in llm:
                    print(f"  Risk Category: {llm['risk_analysis'].get('main_category', 'N/A')}")
            print()
    else:
        print("⚠️  No Azure documents found in index!")
        print("\nChecking for any documents...")
        any_query = {"query": {"match_all": {}}, "size": 5}
        result = client.search(index=index_name, body=any_query)
        if result['hits']['total']['value'] > 0:
            print(f"Found {result['hits']['total']['value']} documents with other providers:")
            for hit in result['hits']['hits']:
                doc = hit['_source']
                print(f"  - {hit['_id']}: provider={doc.get('provider', 'N/A')}")
        else:
            print("  No documents found in index at all!")

    print("=" * 80)

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
