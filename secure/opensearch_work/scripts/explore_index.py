#!/usr/bin/env python3
"""
OpenSearch Index Exploration Script

This script explores the prowler-checks-benchmarks index in OpenSearch,
extracts its mapping, statistics, and sample documents to understand
what the index contains.

Author: Prowler Team
Date: 2024
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('opensearch_work/outputs/exploration.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class OpenSearchExplorer:
    """Handles exploration of OpenSearch indices."""

    def __init__(self, index_name: str = 'prowler-checks-benchmarks'):
        """Initialize the explorer with OpenSearch configuration."""
        self.host = os.getenv('OPENSEARCH_HOST', 'localhost')
        self.port = int(os.getenv('OPENSEARCH_PORT', '9200'))
        # Support both OPENSEARCH_USERNAME and OPENSEARCH_USER
        self.username = os.getenv('OPENSEARCH_USERNAME') or os.getenv('OPENSEARCH_USER')
        self.password = os.getenv('OPENSEARCH_PASSWORD')
        self.index_name = index_name
        # Auto-detect SSL if port is 443, otherwise use env var
        use_ssl_env = os.getenv('OPENSEARCH_USE_SSL', '').lower()
        if use_ssl_env:
            self.use_ssl = use_ssl_env == 'true'
        else:
            # Auto-detect: port 443 typically uses SSL
            self.use_ssl = self.port == 443
        self.verify_certs = os.getenv('OPENSEARCH_VERIFY_CERTS', 'true').lower() == 'true'

        # Try to import opensearch-py
        try:
            from opensearchpy import OpenSearch
            self.OpenSearch = OpenSearch
        except ImportError:
            logger.error("opensearch-py not installed. Install with: pip install opensearch-py")
            sys.exit(1)

        self.client = None
        self.exploration_results = {
            'index_name': self.index_name,
            'timestamp': datetime.now().isoformat(),
            'connection_info': {},
            'index_exists': False,
            'index_stats': {},
            'mapping': {},
            'sample_documents': [],
            'field_analysis': {},
            'summary': {}
        }

    def connect(self) -> bool:
        """Establish connection to OpenSearch."""
        try:
            # Build connection parameters
            connection_params = {
                'hosts': [{'host': self.host, 'port': self.port}],
                'use_ssl': self.use_ssl,
                'verify_certs': self.verify_certs,
                'ssl_assert_hostname': False,
                'ssl_show_warn': False,
            }

            # Add authentication if provided
            if self.username and self.password:
                connection_params['http_auth'] = (self.username, self.password)

            self.client = self.OpenSearch(**connection_params)

            # Test connection
            info = self.client.info()
            logger.info(f"Connected to OpenSearch: {info['version']['number']}")

            self.exploration_results['connection_info'] = {
                'version': info['version']['number'],
                'cluster_name': info.get('cluster_name', 'unknown'),
                'host': self.host,
                'port': self.port
            }

            return True

        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            return False

    def check_index_exists(self) -> bool:
        """Check if the target index exists."""
        try:
            exists = self.client.indices.exists(index=self.index_name)
            self.exploration_results['index_exists'] = exists

            if exists:
                logger.info(f"Index '{self.index_name}' exists")
            else:
                logger.warning(f"Index '{self.index_name}' does not exist")

            return exists

        except Exception as e:
            logger.error(f"Error checking index existence: {e}")
            return False

    def get_index_stats(self) -> Optional[Dict[str, Any]]:
        """Get statistics about the index."""
        try:
            stats = self.client.indices.stats(index=self.index_name)
            index_stats = stats.get('indices', {}).get(self.index_name, {})

            self.exploration_results['index_stats'] = {
                'document_count': index_stats.get('total', {}).get('docs', {}).get('count', 0),
                'deleted_documents': index_stats.get('total', {}).get('docs', {}).get('deleted', 0),
                'store_size_bytes': index_stats.get('total', {}).get('store', {}).get('size_in_bytes', 0),
                'store_size_human': self._format_bytes(index_stats.get('total', {}).get('store', {}).get('size_in_bytes', 0)),
                'indexing_total': index_stats.get('total', {}).get('indexing', {}).get('index_total', 0),
                'search_total': index_stats.get('total', {}).get('search', {}).get('query_total', 0),
            }

            logger.info(f"Index contains {self.exploration_results['index_stats']['document_count']} documents")
            logger.info(f"Index size: {self.exploration_results['index_stats']['store_size_human']}")

            return self.exploration_results['index_stats']

        except Exception as e:
            logger.error(f"Error getting index stats: {e}")
            return None

    def get_index_mapping(self) -> Optional[Dict[str, Any]]:
        """Get the mapping (schema) of the index."""
        try:
            mapping = self.client.indices.get_mapping(index=self.index_name)
            index_mapping = mapping.get(self.index_name, {}).get('mappings', {})

            self.exploration_results['mapping'] = index_mapping

            # Extract field names and types
            properties = index_mapping.get('properties', {})
            field_analysis = self._analyze_mapping(properties)
            self.exploration_results['field_analysis'] = field_analysis

            logger.info(f"Index has {len(properties)} top-level fields")
            logger.info(f"Total fields (including nested): {field_analysis.get('total_fields', 0)}")

            return index_mapping

        except Exception as e:
            logger.error(f"Error getting index mapping: {e}")
            return None

    def _analyze_mapping(self, properties: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """Recursively analyze mapping to extract all fields and their types."""
        fields = {}
        total_fields = 0

        for field_name, field_config in properties.items():
            full_field_name = f"{prefix}.{field_name}" if prefix else field_name
            field_type = field_config.get('type', 'object')

            fields[full_field_name] = {
                'type': field_type,
                'analyzed': field_config.get('index', True) if 'index' in field_config else True,
                'nested': field_type == 'nested' or 'properties' in field_config
            }

            total_fields += 1

            # Recursively analyze nested properties
            if 'properties' in field_config:
                nested_fields, nested_count = self._analyze_mapping_recursive(
                    field_config['properties'], full_field_name
                )
                fields.update(nested_fields)
                total_fields += nested_count

        return {
            'fields': fields,
            'total_fields': total_fields,
            'top_level_fields': len(properties)
        }

    def _analyze_mapping_recursive(self, properties: Dict[str, Any], prefix: str) -> tuple:
        """Helper method for recursive mapping analysis."""
        fields = {}
        count = 0

        for field_name, field_config in properties.items():
            full_field_name = f"{prefix}.{field_name}"
            field_type = field_config.get('type', 'object')

            fields[full_field_name] = {
                'type': field_type,
                'analyzed': field_config.get('index', True) if 'index' in field_config else True,
                'nested': field_type == 'nested' or 'properties' in field_config
            }

            count += 1

            if 'properties' in field_config:
                nested_fields, nested_count = self._analyze_mapping_recursive(
                    field_config['properties'], full_field_name
                )
                fields.update(nested_fields)
                count += nested_count

        return fields, count

    def get_sample_documents(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get sample documents from the index."""
        try:
            # Use search to get sample documents
            response = self.client.search(
                index=self.index_name,
                body={
                    'size': count,
                    'query': {'match_all': {}}
                }
            )

            hits = response.get('hits', {}).get('hits', [])
            documents = []

            for hit in hits:
                doc = {
                    '_id': hit.get('_id'),
                    '_score': hit.get('_score'),
                    '_source': hit.get('_source', {})
                }
                documents.append(doc)

            self.exploration_results['sample_documents'] = documents

            logger.info(f"Retrieved {len(documents)} sample documents")

            return documents

        except Exception as e:
            logger.error(f"Error getting sample documents: {e}")
            return []

    def analyze_document_structure(self) -> Dict[str, Any]:
        """Analyze the structure of sample documents."""
        if not self.exploration_results['sample_documents']:
            return {}

        # Collect all unique keys from sample documents
        all_keys = set()
        key_types = {}
        key_presence = {}

        for doc in self.exploration_results['sample_documents']:
            source = doc.get('_source', {})
            self._extract_keys(source, all_keys, key_types, key_presence)

        # Calculate presence percentage
        total_docs = len(self.exploration_results['sample_documents'])
        key_stats = {}

        for key in all_keys:
            presence_count = key_presence.get(key, 0)
            key_stats[key] = {
                'type': key_types.get(key, 'unknown'),
                'presence_count': presence_count,
                'presence_percentage': (presence_count / total_docs * 100) if total_docs > 0 else 0
            }

        return {
            'unique_keys': sorted(list(all_keys)),
            'total_unique_keys': len(all_keys),
            'key_statistics': key_stats
        }

    def _extract_keys(self, obj: Any, keys: set, key_types: Dict, key_presence: Dict, prefix: str = ''):
        """Recursively extract all keys from a document."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.add(full_key)

                # Track type
                if full_key not in key_types:
                    key_types[full_key] = type(value).__name__

                # Track presence
                key_presence[full_key] = key_presence.get(full_key, 0) + 1

                # Recursively process nested objects
                if isinstance(value, (dict, list)):
                    self._extract_keys(value, keys, key_types, key_presence, full_key)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self._extract_keys(item, keys, key_types, key_presence, prefix)

    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of the index exploration."""
        stats = self.exploration_results['index_stats']
        field_analysis = self.exploration_results['field_analysis']
        doc_analysis = self.analyze_document_structure()

        summary = {
            'index_name': self.index_name,
            'exists': self.exploration_results['index_exists'],
            'document_count': stats.get('document_count', 0),
            'index_size': stats.get('store_size_human', '0 B'),
            'top_level_fields': field_analysis.get('top_level_fields', 0),
            'total_fields': field_analysis.get('total_fields', 0),
            'unique_keys_in_samples': doc_analysis.get('total_unique_keys', 0),
            'sample_documents_analyzed': len(self.exploration_results['sample_documents']),
            'description': self._generate_description()
        }

        self.exploration_results['summary'] = summary
        return summary

    def _generate_description(self) -> str:
        """Generate a human-readable description of what the index contains."""
        if not self.exploration_results['index_exists']:
            return "Index does not exist."

        sample_docs = self.exploration_results['sample_documents']
        if not sample_docs:
            return "Index exists but no documents found."

        # Analyze first document to understand structure
        first_doc = sample_docs[0].get('_source', {})

        description_parts = [
            f"This index contains {self.exploration_results['index_stats'].get('document_count', 0)} documents."
        ]

        # Try to identify what type of data this is
        if 'check' in first_doc:
            description_parts.append("The documents appear to be Prowler security checks.")
            check_info = first_doc.get('check', {})
            if 'id' in check_info:
                description_parts.append(f"Each document has a check ID (e.g., '{check_info.get('id', '')}').")
            if 'title' in check_info:
                description_parts.append(f"Checks have titles describing what they validate.")

        if 'benchmark' in first_doc or 'compliance' in first_doc:
            description_parts.append("The index relates to security benchmarks and compliance frameworks.")

        return " ".join(description_parts)

    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"

    def save_results(self, output_dir: str = 'opensearch_work/data'):
        """Save exploration results to files."""
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save full results as JSON
        results_file = os.path.join(output_dir, f'exploration_results_{timestamp}.json')
        with open(results_file, 'w') as f:
            json.dump(self.exploration_results, f, indent=2, default=str)
        logger.info(f"Saved full results to {results_file}")

        # Save mapping separately
        mapping_file = os.path.join(output_dir, f'index_mapping_{timestamp}.json')
        with open(mapping_file, 'w') as f:
            json.dump(self.exploration_results['mapping'], f, indent=2, default=str)
        logger.info(f"Saved mapping to {mapping_file}")

        # Save sample documents
        samples_file = os.path.join(output_dir, f'sample_documents_{timestamp}.json')
        with open(samples_file, 'w') as f:
            json.dump(self.exploration_results['sample_documents'], f, indent=2, default=str)
        logger.info(f"Saved sample documents to {samples_file}")

        # Save summary as readable text
        summary_file = os.path.join(output_dir, f'index_summary_{timestamp}.txt')
        with open(summary_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"OpenSearch Index Exploration Summary\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Index Name: {self.exploration_results['summary'].get('index_name', 'N/A')}\n")
            f.write(f"Index Exists: {self.exploration_results['summary'].get('exists', False)}\n")
            f.write(f"Document Count: {self.exploration_results['summary'].get('document_count', 0):,}\n")
            f.write(f"Index Size: {self.exploration_results['summary'].get('index_size', '0 B')}\n")
            f.write(f"Top-Level Fields: {self.exploration_results['summary'].get('top_level_fields', 0)}\n")
            f.write(f"Total Fields: {self.exploration_results['summary'].get('total_fields', 0)}\n")
            f.write(f"\nDescription:\n{self.exploration_results['summary'].get('description', 'N/A')}\n")
            f.write("\n" + "=" * 80 + "\n")
            f.write("Field Analysis\n")
            f.write("=" * 80 + "\n\n")

            fields = self.exploration_results['field_analysis'].get('fields', {})
            for field_name, field_info in sorted(fields.items()):
                f.write(f"{field_name}:\n")
                f.write(f"  Type: {field_info.get('type', 'unknown')}\n")
                f.write(f"  Analyzed: {field_info.get('analyzed', True)}\n")
                f.write(f"  Nested: {field_info.get('nested', False)}\n")
                f.write("\n")

        logger.info(f"Saved summary to {summary_file}")

        return {
            'results_file': results_file,
            'mapping_file': mapping_file,
            'samples_file': samples_file,
            'summary_file': summary_file
        }

    def explore(self, sample_count: int = 10) -> Dict[str, Any]:
        """Run the complete exploration process."""
        logger.info(f"Starting exploration of index: {self.index_name}")

        # Connect
        if not self.connect():
            logger.error("Failed to connect to OpenSearch")
            return self.exploration_results

        # Check if index exists
        if not self.check_index_exists():
            logger.warning(f"Index '{self.index_name}' does not exist. Cannot proceed with exploration.")
            return self.exploration_results

        # Get index statistics
        self.get_index_stats()

        # Get mapping
        self.get_index_mapping()

        # Get sample documents
        self.get_sample_documents(sample_count)

        # Generate summary
        self.generate_summary()

        logger.info("Exploration completed successfully!")

        return self.exploration_results


def main():
    """Main function to run the exploration."""
    import argparse

    parser = argparse.ArgumentParser(description='Explore OpenSearch index')
    parser.add_argument('--index', default='prowler-checks-benchmarks',
                       help='Name of the index to explore')
    parser.add_argument('--samples', type=int, default=10,
                       help='Number of sample documents to retrieve')
    parser.add_argument('--output-dir', default='opensearch_work/data',
                       help='Directory to save output files')

    args = parser.parse_args()

    # Initialize explorer
    explorer = OpenSearchExplorer(index_name=args.index)

    # Run exploration
    results = explorer.explore(sample_count=args.samples)

    # Save results
    if results.get('index_exists'):
        saved_files = explorer.save_results(output_dir=args.output_dir)
        logger.info("\n" + "=" * 80)
        logger.info("Exploration Summary")
        logger.info("=" * 80)
        logger.info(f"Index: {results['summary']['index_name']}")
        logger.info(f"Documents: {results['summary']['document_count']:,}")
        logger.info(f"Size: {results['summary']['index_size']}")
        logger.info(f"Fields: {results['summary']['total_fields']}")
        logger.info(f"\nDescription:\n{results['summary']['description']}")
        logger.info("\n" + "=" * 80)
        logger.info("Files saved:")
        for file_type, file_path in saved_files.items():
            logger.info(f"  {file_type}: {file_path}")
    else:
        logger.error("Index does not exist. No files saved.")
        sys.exit(1)


if __name__ == "__main__":
    main()
