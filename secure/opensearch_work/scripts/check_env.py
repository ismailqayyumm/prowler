#!/usr/bin/env python3
"""
Check OpenSearch Environment Variables

This script checks if the required OpenSearch environment variables are set.
"""

import os

def check_env_vars():
    """Check and display OpenSearch environment variables."""
    vars_to_check = [
        'OPENSEARCH_HOST',
        'OPENSEARCH_PORT',
        'OPENSEARCH_USERNAME',
        'OPENSEARCH_PASSWORD',
        'OPENSEARCH_USE_SSL',
        'OPENSEARCH_VERIFY_CERTS',
        'OPENSEARCH_INDEX'
    ]

    print("OpenSearch Environment Variables:")
    print("=" * 60)

    all_set = True
    for var in vars_to_check:
        value = os.getenv(var)
        if value:
            # Mask password
            if 'PASSWORD' in var:
                display_value = '*' * len(value) if value else 'Not set'
            else:
                display_value = value
            print(f"{var:30s}: {display_value}")
        else:
            print(f"{var:30s}: Not set")
            if var in ['OPENSEARCH_HOST', 'OPENSEARCH_USERNAME', 'OPENSEARCH_PASSWORD']:
                all_set = False

    print("=" * 60)

    if all_set:
        print("\n✓ All required environment variables are set!")
    else:
        print("\n✗ Some required environment variables are missing!")
        print("\nRequired variables:")
        print("  - OPENSEARCH_HOST")
        print("  - OPENSEARCH_USERNAME")
        print("  - OPENSEARCH_PASSWORD")
        print("\nOptional variables (with defaults):")
        print("  - OPENSEARCH_PORT (default: 9200)")
        print("  - OPENSEARCH_USE_SSL (default: false)")
        print("  - OPENSEARCH_VERIFY_CERTS (default: true)")
        print("  - OPENSEARCH_INDEX (default: prowler-checks-benchmarks)")

if __name__ == "__main__":
    check_env_vars()
