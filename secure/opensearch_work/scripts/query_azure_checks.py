#!/usr/bin/env python3
"""
Query Azure Checks from OpenSearch

This script queries and displays Azure checks from OpenSearch to help
debug why they might not be showing in the dashboard.
"""

import os
import json
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
print("Querying Azure Checks from OpenSearch")
print("=" * 80)
print(f"Host: {host}:{port}")
print(f"Index: {index_name}")
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

    # Force refresh
    client.indices.refresh(index=index_name)
    print("✓ Index refreshed")
    print()

    # Query 1: All Azure documents
    print("Query 1: All Azure documents")
    print("-" * 80)
    query1 = {
        "query": {
            "term": {
                "provider": "azure"
            }
        },
        "size": 10,
        "sort": [{"created_at": {"order": "desc"}}]
    }

    result1 = client.search(index=index_name, body=query1)
    total = result1['hits']['total']['value']
    print(f"Total Azure documents: {total}")
    print(f"Showing first 10:")
    print()

    for i, hit in enumerate(result1['hits']['hits'], 1):
        doc = hit['_source']
        print(f"{i}. ID: {hit['_id']}")
        print(f"   Title: {doc.get('check', {}).get('title', 'N/A')[:60]}...")
        print(f"   Provider: {doc.get('provider', 'N/A')}")
        print(f"   Module: {doc.get('module', 'N/A')}")
        print(f"   Created: {doc.get('created_at', 'N/A')}")
        print()

    # Query 2: Search by check_id
    print("Query 2: Search by specific check_id")
    print("-" * 80)
    test_check_id = "storage_blob_public_access_level_is_disabled"
    query2 = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"provider": "azure"}},
                    {"term": {"check_id": test_check_id}}
                ]
            }
        }
    }

    result2 = client.search(index=index_name, body=query2)
    if result2['hits']['hits']:
        doc = result2['hits']['hits'][0]['_source']
        print(f"✓ Found: {test_check_id}")
        print(f"  Full document structure:")
        print(json.dumps(list(doc.keys()), indent=2))
    else:
        print(f"✗ Not found: {test_check_id}")

    print()

    # Query 3: Check for documents with specific fields
    print("Query 3: Documents with check.title field")
    print("-" * 80)
    query3 = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"provider": "azure"}},
                    {"exists": {"field": "check.title"}}
                ]
            }
        },
        "size": 5
    }

    result3 = client.search(index=index_name, body=query3)
    print(f"Found: {result3['hits']['total']['value']} documents with check.title")

    print()
    print("=" * 80)
    print("Dashboard Troubleshooting Tips:")
    print("=" * 80)
    print("1. Make sure you're viewing index: prowler-checks-benchmarks")
    print("2. Try searching for: provider:azure")
    print("3. Check if there's a time range filter - remove it")
    print("4. Try refreshing the dashboard (F5 or refresh button)")
    print("5. Check if you have the correct permissions to view the index")
    print("6. Try querying directly:")
    print(f"   GET /{index_name}/_search")
    print('   {"query": {"term": {"provider": "azure"}}}')
    print("=" * 80)

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
