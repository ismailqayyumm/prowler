#!/usr/bin/env python3
"""
OpenSearch Upload Script for Kubernetes Checks

This script uploads the extracted Kubernetes checks data to OpenSearch.
It uses the check ID as the document ID and handles existing documents.

Author: Prowler Team
Date: 2024
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('opensearch_upload.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class OpenSearchUploader:
    """Handles uploading Kubernetes checks data to OpenSearch."""
    
    def __init__(self):
        """Initialize the uploader with OpenSearch configuration."""
        self.host = os.getenv('OPENSEARCH_HOST', 'localhost')
        self.port = int(os.getenv('OPENSEARCH_PORT', '9200'))
        self.username = os.getenv('OPENSEARCH_USERNAME')
        self.password = os.getenv('OPENSEARCH_PASSWORD')
        self.index_name = os.getenv('OPENSEARCH_INDEX', 'prowler-checks-benchmarks')
        self.use_ssl = os.getenv('OPENSEARCH_USE_SSL', 'false').lower() == 'true'
        self.verify_certs = os.getenv('OPENSEARCH_VERIFY_CERTS', 'true').lower() == 'true'
        
        # Try to import opensearch-py
        try:
            from opensearchpy import OpenSearch, helpers
            self.OpenSearch = OpenSearch
            self.helpers = helpers
        except ImportError:
            logger.error("opensearch-py not installed. Install with: pip install opensearch-py")
            sys.exit(1)
        
        self.client = None
        self.stats = {
            'total_documents': 0,
            'successful_uploads': 0,
            'failed_uploads': 0,
            'updated_documents': 0,
            'created_documents': 0,
            'errors': []
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
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            return False
    
    def check_index_exists(self) -> bool:
        """Check if the target index exists."""
        try:
            return self.client.indices.exists(index=self.index_name)
        except Exception as e:
            logger.error(f"Error checking index existence: {e}")
            return False
    
    def create_index_if_not_exists(self) -> bool:
        """Create the index if it doesn't exist."""
        try:
            if not self.check_index_exists():
                logger.info(f"Creating index: {self.index_name}")
                
                # Load the index mapping
                mapping_file = 'index-mapping.json'
                if os.path.exists(mapping_file):
                    with open(mapping_file, 'r') as f:
                        mapping = json.load(f)
                    
                    # Extract the mapping for our index
                    if self.index_name in mapping:
                        self.client.indices.create(
                            index=self.index_name,
                            body=mapping[self.index_name]
                        )
                        logger.info(f"Index {self.index_name} created successfully")
                    else:
                        logger.warning(f"Index mapping not found for {self.index_name}, creating with default mapping")
                        self.client.indices.create(index=self.index_name)
                else:
                    logger.warning(f"Mapping file {mapping_file} not found, creating with default mapping")
                    self.client.indices.create(index=self.index_name)
            else:
                logger.info(f"Index {self.index_name} already exists")
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating index: {e}")
            return False
    
    def check_document_exists(self, doc_id: str) -> bool:
        """Check if a document with the given ID already exists."""
        try:
            return self.client.exists(index=self.index_name, id=doc_id)
        except Exception as e:
            logger.warning(f"Error checking document existence for {doc_id}: {e}")
            return False
    
    def upload_single_document(self, doc_data: Dict[str, Any], doc_id: str) -> bool:
        """Upload a single document to OpenSearch."""
        try:
            # Check if document exists
            doc_exists = self.check_document_exists(doc_id)
            
            # Prepare the document
            document = {
                '_index': self.index_name,
                '_id': doc_id,
                '_source': doc_data
            }
            
            if doc_exists:
                # Update existing document
                result = self.client.index(
                    index=self.index_name,
                    id=doc_id,
                    body=doc_data,
                    refresh=True
                )
                self.stats['updated_documents'] += 1
                logger.debug(f"Updated document: {doc_id}")
            else:
                # Create new document
                result = self.client.index(
                    index=self.index_name,
                    id=doc_id,
                    body=doc_data,
                    refresh=True
                )
                self.stats['created_documents'] += 1
                logger.debug(f"Created document: {doc_id}")
            
            self.stats['successful_uploads'] += 1
            return True
            
        except Exception as e:
            error_msg = f"Failed to upload document {doc_id}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            self.stats['failed_uploads'] += 1
            return False
    
    def bulk_upload_documents(self, documents: List[Dict[str, Any]]) -> bool:
        """Upload multiple documents using bulk API."""
        try:
            # Prepare bulk actions
            actions = []
            for doc in documents:
                doc_id = doc.get('check', {}).get('id', '')
                if not doc_id:
                    logger.warning("Document missing check ID, skipping")
                    continue
                
                action = {
                    '_index': self.index_name,
                    '_id': doc_id,
                    '_source': doc
                }
                actions.append(action)
            
            # Execute bulk upload
            success_count, failed_items = self.helpers.bulk(
                self.client,
                actions,
                refresh=True,
                stats_only=False
            )
            
            self.stats['successful_uploads'] += success_count
            self.stats['failed_uploads'] += len(failed_items) if failed_items else 0
            
            if failed_items:
                for item in failed_items:
                    error_msg = f"Bulk upload failed for item: {item}"
                    logger.error(error_msg)
                    self.stats['errors'].append(error_msg)
            
            logger.info(f"Bulk upload completed: {success_count} successful, {len(failed_items) if failed_items else 0} failed")
            return len(failed_items) == 0 if failed_items else True
            
        except Exception as e:
            logger.error(f"Bulk upload failed: {e}")
            self.stats['errors'].append(f"Bulk upload error: {e}")
            return False
    
    def load_extracted_data(self, file_path: str) -> List[Dict[str, Any]]:
        """Load the extracted Kubernetes checks data."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if 'checks' in data:
                documents = data['checks']
            else:
                # Handle bulk format (one JSON object per line)
                documents = []
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                doc = json.loads(line)
                                documents.append(doc)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Failed to parse line: {e}")
                                continue
            
            logger.info(f"Loaded {len(documents)} documents from {file_path}")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to load data from {file_path}: {e}")
            return []
    
    def upload_data(self, data_file: str, use_bulk: bool = True) -> bool:
        """Upload the extracted data to OpenSearch."""
        try:
            # Load data
            documents = self.load_extracted_data(data_file)
            if not documents:
                logger.error("No documents to upload")
                return False
            
            self.stats['total_documents'] = len(documents)
            
            # Create index if needed
            if not self.create_index_if_not_exists():
                return False
            
            # Upload data
            if use_bulk and len(documents) > 1:
                logger.info(f"Starting bulk upload of {len(documents)} documents...")
                success = self.bulk_upload_documents(documents)
            else:
                logger.info(f"Starting individual upload of {len(documents)} documents...")
                success = True
                for doc in documents:
                    doc_id = doc.get('check', {}).get('id', '')
                    if doc_id:
                        if not self.upload_single_document(doc, doc_id):
                            success = False
                    else:
                        logger.warning("Document missing check ID, skipping")
                        self.stats['failed_uploads'] += 1
            
            # Print summary
            self.print_summary()
            return success
            
        except Exception as e:
            logger.error(f"Upload process failed: {e}")
            return False
    
    def print_summary(self):
        """Print upload summary."""
        logger.info("=== UPLOAD SUMMARY ===")
        logger.info(f"Total documents: {self.stats['total_documents']}")
        logger.info(f"Successful uploads: {self.stats['successful_uploads']}")
        logger.info(f"Failed uploads: {self.stats['failed_uploads']}")
        logger.info(f"Created documents: {self.stats['created_documents']}")
        logger.info(f"Updated documents: {self.stats['updated_documents']}")
        
        if self.stats['errors']:
            logger.info(f"Errors encountered: {len(self.stats['errors'])}")
            for error in self.stats['errors'][:5]:  # Show first 5 errors
                logger.error(f"  - {error}")

def main():
    """Main function to run the upload process."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Upload Kubernetes checks to OpenSearch')
    parser.add_argument('--data-file', default='kubernetes_checks_opensearch.json',
                       help='Path to the extracted data file')
    parser.add_argument('--bulk', action='store_true', default=True,
                       help='Use bulk upload (default: True)')
    parser.add_argument('--individual', action='store_true',
                       help='Use individual document upload')
    
    args = parser.parse_args()
    
    # Override bulk setting if individual is specified
    use_bulk = args.bulk and not args.individual
    
    # Initialize uploader
    uploader = OpenSearchUploader()
    
    # Connect to OpenSearch
    if not uploader.connect():
        logger.error("Failed to connect to OpenSearch. Check your credentials and connection settings.")
        sys.exit(1)
    
    # Upload data
    success = uploader.upload_data(args.data_file, use_bulk=use_bulk)
    
    if success:
        logger.info("Upload completed successfully!")
        sys.exit(0)
    else:
        logger.error("Upload completed with errors!")
        sys.exit(1)

if __name__ == "__main__":
    main()