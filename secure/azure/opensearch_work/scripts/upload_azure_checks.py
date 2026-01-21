#!/usr/bin/env python3
"""
Upload Azure Checks to OpenSearch Index

This script reads the Azure checks CSV with LLM risk labels and uploads
them to the prowler-checks-benchmarks OpenSearch index.

Author: Prowler Team
Date: 2025
"""

import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Get script directory and set up paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent

# Load environment variables from .env file if it exists (BEFORE logging setup)
ENV_FILE = PROJECT_ROOT / '.env'
if ENV_FILE.exists():
    with open(ENV_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # Only set if not already in environment
                if key not in os.environ:
                    os.environ[key] = value

# Set up output directory
OUTPUTS_DIR = PROJECT_ROOT / 'opensearch_work' / 'outputs'
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(OUTPUTS_DIR / 'upload.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AzureChecksUploader:
    """Handles uploading Azure checks to OpenSearch."""

    def __init__(self, index_name: str = 'prowler-checks-benchmarks'):
        """Initialize the uploader with OpenSearch configuration."""
        self.host = os.getenv('OPENSEARCH_HOST', 'localhost')
        self.port = int(os.getenv('OPENSEARCH_PORT', '9200'))
        self.username = os.getenv('OPENSEARCH_USERNAME') or os.getenv('OPENSEARCH_USER')
        self.password = os.getenv('OPENSEARCH_PASSWORD')
        self.index_name = index_name

        # Auto-detect SSL if port is 443
        use_ssl_env = os.getenv('OPENSEARCH_USE_SSL', '').lower()
        if use_ssl_env:
            self.use_ssl = use_ssl_env == 'true'
        else:
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

        # Azure frameworks (12 total)
        self.azure_frameworks = [
            "ccc_azure",
            "cis_2_0_azure",
            "cis_2_1_azure",
            "cis_3_0_azure",
            "cis_4_0_azure",
            "ens_rd2022_azure",
            "iso27001_2022_azure",
            "mitre_attack_azure",
            "nis2_azure",
            "pci_4_0_azure",
            "prowler_threatscore_azure",
            "soc2_azure"
        ]

    def connect(self) -> bool:
        """Establish connection to OpenSearch."""
        try:
            connection_params = {
                'hosts': [{'host': self.host, 'port': self.port}],
                'use_ssl': self.use_ssl,
                'verify_certs': self.verify_certs,
                'ssl_assert_hostname': False,
                'ssl_show_warn': False,
            }

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

    def parse_array_field(self, value: str) -> List[str]:
        """Parse comma-separated string into array."""
        if not value or value.strip() == '':
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def parse_boolean(self, value: str) -> Optional[bool]:
        """Parse boolean string to boolean."""
        if not value or value.strip() == '':
            return None
        val = str(value).strip().lower()
        if val in ('true', '1', 'yes'):
            return True
        elif val in ('false', '0', 'no'):
            return False
        return None

    def parse_float(self, value: str) -> Optional[float]:
        """Parse string to float."""
        if not value or value.strip() == '' or value.strip().lower() == 'na':
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    def parse_date(self, value: str) -> Optional[str]:
        """Parse date string (already in ISO format)."""
        if not value or value.strip() == '':
            return None
        return value.strip()

    def convert_confidence(self, value: str) -> Optional[int]:
        """Convert confidence from 0.0-1.0 to 0-100."""
        if not value or value.strip() == '':
            return None
        try:
            float_val = float(value)
            return int(float_val * 100)
        except (ValueError, TypeError):
            return None

    def build_check_object(self, row: Dict) -> Dict:
        """Build check nested object."""
        check = {
            "id": row.get('check_id_field', row.get('check_id', '')),
            "title": row.get('check_title', ''),
            "description": row.get('check_description', ''),
            "service": row.get('check_service', ''),
            "sub_service": row.get('check_sub_service', '') or '',
            "severity": row.get('check_severity', '').lower() if row.get('check_severity') else '',
            "resource_type": row.get('check_resource_type', ''),
            "risk": row.get('check_risk', ''),
            "score": self.parse_float(row.get('check_score', '')),
            "type": self.parse_array_field(row.get('check_type', '')),
            "categories": self.parse_array_field(row.get('check_categories', '')),
            "depends_on": self.parse_array_field(row.get('check_depends_on', '')),
            "related_to": self.parse_array_field(row.get('check_related_to', '')),
            "related_url": row.get('check_related_url', '') or '',
            "notes": row.get('check_notes', '') or ''
        }

        # Remove empty fields
        return {k: v for k, v in check.items() if v not in (None, '', [])}

    def build_remediation_object(self, row: Dict) -> Dict:
        """Build remediation nested object."""
        remediation = {
            "cli": row.get('remediation_cli', '') or '',
            "terraform": row.get('remediation_terraform', '') or '',
            "cloudformation": row.get('remediation_cloudformation', '') or '',
            "other": row.get('remediation_other', '') or '',
            "recommendation_text": row.get('remediation_recommendation_text', '') or '',
            "recommendation_url": row.get('remediation_recommendation_url', '') or ''
        }

        # Remove empty fields
        return {k: v for k, v in remediation.items() if v}

    def build_finalized_object(self, row: Dict) -> Dict:
        """Build finalized nested object."""
        finalized = {
            "main_category": row.get('finalized_main_category', '') or '',
            "sub_category": row.get('finalized_sub_category', '') or '',
            "main": row.get('finalized_main', '') or '',
            "sub": row.get('finalized_sub', '') or ''
        }

        # Remove empty fields
        return {k: v for k, v in finalized.items() if v}

    def build_benchmarks_object(self, row: Dict) -> Dict:
        """Build benchmarks nested object."""
        benchmarks = {}

        for framework in self.azure_frameworks:
            exists_key = f"benchmark_{framework}_exists"
            value_key = f"benchmark_{framework}_value"
            desc_key = f"benchmark_{framework}_description"

            exists = self.parse_boolean(row.get(exists_key, ''))
            value = row.get(value_key, '').strip()
            description = row.get(desc_key, '').strip()

            # Only include if exists is True or value is not NA
            if exists is True or (value and value.upper() != 'NA'):
                benchmarks[framework] = {
                    "exists": exists if exists is not None else False,
                    "value": value if value and value.upper() != 'NA' else "NA",
                    "description": description if description and description.upper() != 'NA' else "NA"
                }

        return benchmarks

    def build_attributes_array(self, row: Dict) -> List[Dict]:
        """Build attributes array (only first attribute from CSV)."""
        attributes = []

        # Check if we have any attribute data
        if row.get('attributes_section') or row.get('attributes_description'):
            attr = {}

            if row.get('attributes_section'):
                attr['Section'] = row['attributes_section']
            if row.get('attributes_subsection'):
                attr['SubSection'] = row['attributes_subsection']
            if row.get('attributes_profile'):
                attr['Profile'] = row['attributes_profile']
            if row.get('attributes_assessment_status'):
                attr['AssessmentStatus'] = row['attributes_assessment_status']
            if row.get('attributes_description'):
                attr['Description'] = row['attributes_description']
            if row.get('attributes_impact_statement'):
                attr['ImpactStatement'] = row['attributes_impact_statement']
            if row.get('attributes_rationale_statement'):
                attr['RationaleStatement'] = row['attributes_rationale_statement']
            if row.get('attributes_service'):
                attr['Service'] = row['attributes_service']

            if attr:
                attributes.append(attr)

        return attributes

    def build_llm_object(self, row: Dict) -> Optional[Dict]:
        """Build LLM nested object."""
        # Helper to check if a field has a non-empty value
        def has_value(field_name: str) -> bool:
            value = row.get(field_name)
            if value is None:
                return False
            return str(value).strip() != ''

        # Check if we have any LLM data (must have non-empty values)
        if not any([
            has_value('mitre_technique_id'),
            has_value('mitre_tactic'),
            has_value('mitre_technique_name'),
            has_value('risk_main_category'),
            has_value('risk_sub_category')
        ]):
            return None

        llm = {}

        # MITRE Analysis
        mitre_analysis = {}
        has_mitre_data = False

        if has_value('mitre_technique_id'):
            mitre_analysis['technique_id'] = str(row['mitre_technique_id']).strip()
            has_mitre_data = True

        if has_value('mitre_technique_name'):
            mitre_analysis['technique_name'] = str(row['mitre_technique_name']).strip()
            has_mitre_data = True

        if has_value('mitre_tactic'):
            # Store as single string value
            mitre_analysis['tactics'] = str(row['mitre_tactic']).strip()
            has_mitre_data = True

        # Confidence and reason for MITRE analysis
        confidence = self.convert_confidence(row.get('llm_confidence', ''))
        if confidence is not None:
            mitre_analysis['confidence'] = confidence
            has_mitre_data = True

        if has_value('llm_reasoning'):
            mitre_analysis['reason'] = str(row['llm_reasoning']).strip()
            has_mitre_data = True

        if has_mitre_data and mitre_analysis:
            llm['mitre_analysis'] = mitre_analysis

        # Risk Analysis
        risk_analysis = {}
        has_risk_data = False

        if has_value('risk_main_category'):
            risk_analysis['main_category'] = str(row['risk_main_category']).strip()
            has_risk_data = True

        if has_value('risk_sub_category'):
            # Store as single string value
            risk_analysis['sub_categories'] = str(row['risk_sub_category']).strip()
            has_risk_data = True

        # Confidence and reason for risk analysis
        confidence = self.convert_confidence(row.get('llm_confidence', ''))
        if confidence is not None:
            risk_analysis['categorization_confidence'] = confidence
            has_risk_data = True

        if has_value('llm_reasoning'):
            risk_analysis['categorization_reason'] = str(row['llm_reasoning']).strip()
            has_risk_data = True

        # Business impact - optional field from CSV, if not available can be derived from reasoning
        if has_value('llm_business_impact'):
            risk_analysis['business_impact'] = str(row['llm_business_impact']).strip()
            has_risk_data = True
        elif has_value('llm_reasoning'):
            # If business_impact not provided, we can use reasoning as a fallback
            # This matches the structure where business_impact explains the impact
            pass  # Don't duplicate reasoning, leave business_impact empty if not in CSV

        if has_risk_data and risk_analysis:
            llm['risk_analysis'] = risk_analysis

        # Overall LLM metadata - only add if we have actual analysis data
        if llm:
            confidence = self.convert_confidence(row.get('llm_confidence', ''))
            if confidence is not None:
                llm['overall_confidence'] = confidence

            llm['model_used'] = 'claude-3-7-sonnet'
            # analysis_timestamp should be a date - OpenSearch accepts ISO format strings
            llm['analysis_timestamp'] = datetime.now().isoformat()

        return llm if llm else None

    def transform_row_to_document(self, row: Dict) -> Dict:
        """Transform CSV row to OpenSearch document."""
        check_id = row.get('check_id', '')

        doc = {
            "check_id": check_id,
            "provider": row.get('provider', 'azure'),
            "module": row.get('module', ''),
            "checks": check_id,  # Add checks field (keyword) - same as check_id
            "check": self.build_check_object(row),
            "remediation": self.build_remediation_object(row),
            "finalized": self.build_finalized_object(row),
            "benchmarks": self.build_benchmarks_object(row),
            "attributes": self.build_attributes_array(row),
        }

        # Add LLM object if available (only if we have LLM data)
        llm_obj = self.build_llm_object(row)
        if llm_obj:
            doc['llm'] = llm_obj

        # Add timestamps - always use current timestamp for created_at and updated_at
        # Use UTC with 'Z' suffix for proper OpenSearch date field indexing
        current_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        doc['created_at'] = current_timestamp
        doc['updated_at'] = current_timestamp

        return doc

    def upload_csv(self, csv_path: str, batch_size: int = 100) -> Dict[str, Any]:
        """Upload CSV data to OpenSearch."""
        csv_file = Path(csv_path)
        if not csv_file.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_file}")

        logger.info(f"Reading CSV file: {csv_file}")

        documents = []
        total_rows = 0
        errors = []

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, 1):
                try:
                    doc = self.transform_row_to_document(row)
                    check_id = doc['check_id']

                    # Use check_id as document ID
                    documents.append({
                        "_index": self.index_name,
                        "_id": check_id,
                        "_source": doc
                    })

                    total_rows += 1

                    # Upload in batches
                    if len(documents) >= batch_size:
                        self._bulk_upload(documents, errors)
                        documents = []
                        logger.info(f"Processed {total_rows} rows...")

                except Exception as e:
                    error_msg = f"Error processing row {row_num}: {e}"
                    logger.error(error_msg)
                    errors.append({
                        "row": row_num,
                        "error": str(e),
                        "check_id": row.get('check_id', 'unknown')
                    })

        # Upload remaining documents
        if documents:
            self._bulk_upload(documents, errors)

        logger.info(f"Upload complete. Total rows: {total_rows}, Errors: {len(errors)}")

        return {
            "total_rows": total_rows,
            "errors": errors,
            "success_count": total_rows - len(errors)
        }

    def _bulk_upload(self, documents: List[Dict], errors: List[Dict]):
        """Upload batch of documents using bulk API."""
        try:
            from opensearchpy.helpers import bulk

            success, failed = bulk(self.client, documents, raise_on_error=False)

            if failed:
                for item in failed:
                    errors.append({
                        "check_id": item.get('index', {}).get('_id', 'unknown'),
                        "error": item.get('index', {}).get('error', {}).get('reason', 'Unknown error')
                    })
                    logger.warning(f"Failed to index {item.get('index', {}).get('_id')}: {item.get('index', {}).get('error', {}).get('reason')}")

            logger.info(f"Uploaded batch: {success} successful, {len(failed)} failed")

        except Exception as e:
            logger.error(f"Bulk upload error: {e}")
            for doc in documents:
                errors.append({
                    "check_id": doc.get('_id', 'unknown'),
                    "error": str(e)
                })


def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(description='Upload Azure checks to OpenSearch')
    parser.add_argument('--csv', '-c',
                       default=str(PROJECT_ROOT / 'opensearch_work' / 'data' / 'azure_checks_with_llm_risk_labels.csv'),
                       help='Path to CSV file (default: opensearch_work/data/azure_checks_with_llm_risk_labels.csv)')
    parser.add_argument('--index', '-i',
                       default='prowler-checks-benchmarks',
                       help='OpenSearch index name (default: prowler-checks-benchmarks)')
    parser.add_argument('--batch-size', '-b',
                       type=int, default=100,
                       help='Batch size for bulk upload (default: 100)')

    args = parser.parse_args()

    # Check environment variables
    required_vars = ['OPENSEARCH_HOST', 'OPENSEARCH_PORT']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)

    try:
        uploader = AzureChecksUploader(index_name=args.index)

        if not uploader.connect():
            logger.error("Failed to connect to OpenSearch")
            sys.exit(1)

        logger.info("=" * 80)
        logger.info("Uploading Azure Checks to OpenSearch")
        logger.info("=" * 80)
        logger.info(f"Index: {args.index}")
        logger.info(f"CSV File: {args.csv}")
        logger.info(f"Batch Size: {args.batch_size}")
        logger.info("=" * 80)

        results = uploader.upload_csv(args.csv, batch_size=args.batch_size)

        logger.info("=" * 80)
        logger.info("Upload Summary")
        logger.info("=" * 80)
        logger.info(f"Total rows processed: {results['total_rows']}")
        logger.info(f"Successful uploads: {results['success_count']}")
        logger.info(f"Errors: {len(results['errors'])}")

        if results['errors']:
            logger.warning(f"\nFirst 10 errors:")
            for error in results['errors'][:10]:
                logger.warning(f"  - {error['check_id']}: {error['error']}")
            if len(results['errors']) > 10:
                logger.warning(f"  ... and {len(results['errors']) - 10} more errors")

        logger.info("=" * 80)

        if results['errors']:
            # Save errors to file
            errors_file = OUTPUTS_DIR / 'upload_errors.json'
            with open(errors_file, 'w') as f:
                json.dump(results['errors'], f, indent=2)
            logger.info(f"Errors saved to: {errors_file}")

        print(f"\n✅ Upload complete!")
        print(f"📊 Successfully uploaded: {results['success_count']}/{results['total_rows']} documents")

    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
