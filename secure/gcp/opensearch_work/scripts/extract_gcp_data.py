#!/usr/bin/env python3
"""
Extract GCP Check Data for OpenSearch Index

This script extracts all GCP security checks from the Prowler repository,
maps them to compliance frameworks, calculates risk scores, and generates
a CSV file with all required fields for the prowler-checks-benchmarks index.

Author: Prowler Team
Date: 2025
"""

import json
import os
import sys
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Get script directory and set up paths
SCRIPT_DIR = Path(__file__).parent
# Go up from: secure/gcp/opensearch_work/scripts -> secure/gcp/opensearch_work -> secure/gcp -> secure -> project root
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent.parent

# Configure logging
OUTPUTS_DIR = PROJECT_ROOT / 'secure' / 'gcp' / 'opensearch_work' / 'outputs'
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(OUTPUTS_DIR / 'gcp_extraction.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class GCPDataExtractor:
    """Extracts and processes GCP check data for OpenSearch indexing."""

    def __init__(self, prowler_root: str = None):
        """Initialize the extractor."""
        if prowler_root is None:
            prowler_root = PROJECT_ROOT
        self.prowler_root = Path(prowler_root)
        self.provider = "gcp"

        # GCP compliance frameworks (12 total)
        # Note: Framework keys use underscores instead of dots (e.g., "cis_2_0_gcp" not "cis_2.0_gcp")
        self.gcp_frameworks = [
            "ccc_gcp",
            "cis_2_0_gcp",
            "cis_3_0_gcp",
            "cis_4_0_gcp",
            "ens_rd2022_gcp",
            "iso27001_2022_gcp",
            "mitre_attack_gcp",
            "nis2_gcp",
            "pci_4_0_gcp",
            "prowler_threatscore_gcp",
            "soc2_gcp"
        ]

        # Map from file names (with dots) to index keys (with underscores)
        self.framework_file_to_key = {
            "ccc_gcp": "ccc_gcp",
            "cis_2.0_gcp": "cis_2_0_gcp",
            "cis_3.0_gcp": "cis_3_0_gcp",
            "cis_4.0_gcp": "cis_4_0_gcp",
            "ens_rd2022_gcp": "ens_rd2022_gcp",
            "iso27001_2022_gcp": "iso27001_2022_gcp",
            "mitre_attack_gcp": "mitre_attack_gcp",
            "nis2_gcp": "nis2_gcp",
            "pci_4.0_gcp": "pci_4_0_gcp",
            "prowler_threatscore_gcp": "prowler_threatscore_gcp",
            "soc2_gcp": "soc2_gcp"
        }

        self.checks_metadata = {}
        self.compliance_frameworks = {}
        self.extracted_data = []

    def load_gcp_checks(self) -> Dict[str, Dict]:
        """Load all GCP check metadata from JSON files."""
        logger.info("Loading GCP checks metadata...")
        self.checks_metadata = {}

        providers_dir = self.prowler_root / "prowler" / "providers" / "gcp" / "services"

        if not providers_dir.exists():
            raise FileNotFoundError(f"GCP providers directory not found: {providers_dir}")

        # Walk through all services
        check_count = 0
        for service_dir in providers_dir.iterdir():
            if not service_dir.is_dir() or service_dir.name.startswith('_'):
                continue

            # Look for check directories
            for check_dir in service_dir.iterdir():
                if not check_dir.is_dir() or check_dir.name.startswith('_'):
                    continue

                # Look for metadata.json file
                metadata_file = check_dir / f"{check_dir.name}.metadata.json"
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r', encoding='utf-8') as f:
                            check_data = json.load(f)

                        check_id = check_data.get('CheckID')
                        if check_id:
                            self.checks_metadata[check_id] = check_data
                            check_count += 1
                    except Exception as e:
                        logger.warning(f"Error loading {metadata_file}: {e}")

        logger.info(f"Loaded {check_count} GCP checks")
        return self.checks_metadata

    def load_compliance_frameworks(self) -> Dict[str, Dict]:
        """Load all GCP compliance frameworks from JSON files."""
        logger.info("Loading GCP compliance frameworks...")
        self.compliance_frameworks = {}

        compliance_dir = self.prowler_root / "prowler" / "compliance" / "gcp"

        if not compliance_dir.exists():
            raise FileNotFoundError(f"GCP compliance directory not found: {compliance_dir}")

        # Load frameworks from file names (with dots) and map to index keys (with underscores)
        for file_name, index_key in self.framework_file_to_key.items():
            framework_path = compliance_dir / f"{file_name}.json"
            if framework_path.exists():
                try:
                    with open(framework_path, 'r', encoding='utf-8') as f:
                        framework_data = json.load(f)

                    # Store with index key format (underscores)
                    self.compliance_frameworks[index_key] = framework_data
                    logger.debug(f"Loaded framework: {file_name} -> {index_key}")
                except Exception as e:
                    logger.warning(f"Error loading framework {file_name}: {e}")
            else:
                logger.warning(f"Framework file not found: {framework_path}")

        logger.info(f"Loaded {len(self.compliance_frameworks)} compliance frameworks")
        return self.compliance_frameworks

    def map_checks_to_compliance(self):
        """Map checks to compliance frameworks."""
        logger.info("Mapping checks to compliance frameworks...")

        # Build a reverse mapping: check_id -> list of (framework_key, requirement)
        check_to_frameworks = {}

        for framework_key, framework_data in self.compliance_frameworks.items():
            requirements = framework_data.get('Requirements', [])
            for requirement in requirements:
                check_ids = requirement.get('Checks', [])
                for check_id in check_ids:
                    if check_id not in check_to_frameworks:
                        check_to_frameworks[check_id] = []
                    check_to_frameworks[check_id].append({
                        'framework': framework_key,
                        'requirement': requirement
                    })

        # Store compliance mapping in check metadata
        for check_id, check_data in self.checks_metadata.items():
            check_data['_compliance_mapping'] = check_to_frameworks.get(check_id, [])

        logger.info("Compliance mapping completed")

    def calculate_risk_score(self, check_data: Dict) -> float:
        """
        Calculate risk score based on severity, categories, and compliance coverage.

        Scoring:
        - Severity: critical=5.0, high=4.0, medium=3.0, low=2.0, informational=1.0
        - Categories: internet-exposed=+1.0, encryption=+0.5, access-control=+0.5
        - Compliance coverage: +0.1 per framework that includes this check
        - Profile level: Level 2 = +0.5
        """
        score = 0.0

        # Base score from severity
        severity = check_data.get('Severity', 'medium').lower()
        severity_scores = {
            "critical": 5.0,
            "high": 4.0,
            "medium": 3.0,
            "low": 2.0,
            "informational": 1.0
        }
        score += severity_scores.get(severity, 2.0)

        # Category bonuses
        category_bonuses = {
            "internet-exposed": 1.0,
            "encryption": 0.5,
            "access-control": 0.5,
            "data-protection": 0.5,
            "logging": 0.3,
            "backup": 0.3
        }
        categories = check_data.get('Categories', [])
        for category in categories:
            score += category_bonuses.get(category.lower(), 0.0)

        # Compliance framework coverage bonus
        compliance_mapping = check_data.get('_compliance_mapping', [])
        score += len(compliance_mapping) * 0.1

        # Profile level bonus (from compliance attributes)
        for mapping in compliance_mapping:
            requirement = mapping.get('requirement', {})
            attributes = requirement.get('Attributes', [])
            for attr in attributes:
                profile = attr.get('Profile', '')
                if profile and ('Level 2' in str(profile) or 'Level 2' in profile):
                    score += 0.5
                    break

        # Cap at 10.0
        return min(round(score, 2), 10.0)

    def extract_benchmarks(self, check_data: Dict) -> Dict[str, Dict[str, Any]]:
        """Extract benchmark mappings for a check."""
        benchmarks = {}

        # Initialize all GCP frameworks
        for framework_key in self.gcp_frameworks:
            benchmarks[framework_key] = {
                "exists": False,
                "value": "NA",
                "description": "NA"
            }

        # Map actual compliance
        compliance_mapping = check_data.get('_compliance_mapping', [])
        for mapping in compliance_mapping:
            framework_key = mapping.get('framework')
            requirement = mapping.get('requirement', {})

            if framework_key and framework_key in benchmarks:
                benchmarks[framework_key]["exists"] = True
                benchmarks[framework_key]["value"] = requirement.get('Id', 'NA')
                benchmarks[framework_key]["description"] = requirement.get('Description', 'NA')

        return benchmarks

    def extract_attributes(self, check_data: Dict) -> List[Dict[str, Any]]:
        """Extract compliance framework attributes for a check."""
        attributes = []

        compliance_mapping = check_data.get('_compliance_mapping', [])
        for mapping in compliance_mapping:
            requirement = mapping.get('requirement', {})
            req_attributes = requirement.get('Attributes', [])

            for attr in req_attributes:
                attr_dict = {}

                # Extract all possible attribute fields
                for field in [
                    'Section', 'SubSection', 'Profile', 'AssessmentStatus',
                    'Description', 'RationaleStatement', 'ImpactStatement',
                    'RemediationProcedure', 'AuditProcedure', 'References',
                    'Service', 'Category', 'Check_Summary', 'DefaultValue',
                    'AdditionalInformation', 'Objetive_ID', 'Objetive_Name',
                    'GCPService', 'LevelOfRisk', 'Weight'
                ]:
                    if field in attr:
                        attr_dict[field] = attr[field]

                if attr_dict:
                    attributes.append(attr_dict)

        return attributes

    def categorize_check(self, check_data: Dict) -> Dict[str, str]:
        """Categorize check into main and sub categories."""
        categories = {
            "main_category": "",
            "sub_category": ""
        }

        # Map categories to main categories
        category_mapping = {
            "internet-exposed": "Data Exposure",
            "encryption": "Data Protection",
            "access-control": "Access Control",
            "data-protection": "Data Protection",
            "logging": "Monitoring & Logging",
            "backup": "Backup & Recovery",
            "networking": "Network Security",
            "authentication": "Access Control",
            "authorization": "Access Control"
        }

        check_categories = check_data.get('Categories', [])
        if check_categories:
            # Use first category to determine main category
            first_category = check_categories[0].lower()
            categories["main_category"] = category_mapping.get(first_category, "Security Configuration")
            categories["sub_category"] = check_categories[0] if check_categories else ""

        # Fallback to CheckType if no categories
        if not categories["main_category"]:
            check_type = check_data.get('CheckType', [])
            if check_type:
                type_mapping = {
                    "Data Protection": "Data Protection",
                    "Access Control": "Access Control",
                    "Networking": "Network Security"
                }
                categories["main_category"] = type_mapping.get(check_type[0], "Security Configuration")

        return categories

    def extract_check_data(self, check_id: str, check_data: Dict) -> Dict[str, Any]:
        """Extract all data for a single check."""
        # Calculate risk score
        risk_score = self.calculate_risk_score(check_data)

        # Extract benchmarks
        benchmarks = self.extract_benchmarks(check_data)

        # Extract attributes
        attributes = self.extract_attributes(check_data)

        # Categorize
        categories = self.categorize_check(check_data)

        # Build check object
        check_obj = {
            "id": check_data.get('CheckID', check_id),
            "title": check_data.get('CheckTitle', ''),
            "description": check_data.get('Description', ''),
            "service": check_data.get('ServiceName', ''),
            "sub_service": check_data.get('SubServiceName', ''),
            "severity": check_data.get('Severity', 'medium').lower(),
            "resource_type": check_data.get('ResourceType', ''),
            "risk": check_data.get('Risk', ''),
            "score": risk_score,
            "type": check_data.get('CheckType', []),
            "categories": check_data.get('Categories', []),
            "depends_on": check_data.get('DependsOn', []),
            "related_to": check_data.get('RelatedTo', []),
            "related_url": check_data.get('RelatedUrl', ''),
            "notes": check_data.get('Notes', '')
        }

        # Build remediation object
        remediation_data = check_data.get('Remediation', {})
        code_data = remediation_data.get('Code', {})
        recommendation_data = remediation_data.get('Recommendation', {})

        remediation = {
            "cli": code_data.get('CLI', ''),
            "terraform": code_data.get('Terraform', ''),
            "cloudformation": code_data.get('NativeIaC', ''),
            "other": code_data.get('Other', ''),
            "recommendation_text": recommendation_data.get('Text', ''),
            "recommendation_url": recommendation_data.get('Url', '')
        }

        # Build finalized categories
        finalized = {
            "main_category": categories["main_category"],
            "sub_category": categories["sub_category"],
            "main": categories["main_category"],
            "sub": categories["sub_category"]
        }

        # Build document
        document = {
            "check_id": check_id,
            "provider": "gcp",
            "module": check_data.get('ServiceName', ''),
            "check": check_obj,
            "benchmarks": benchmarks,
            "attributes": attributes,
            "remediation": remediation,
            "finalized": finalized,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }

        return document

    def extract_all_data(self):
        """Extract data for all GCP checks."""
        logger.info("Starting data extraction for all GCP checks...")

        # Load data
        self.load_gcp_checks()
        self.load_compliance_frameworks()
        self.map_checks_to_compliance()

        # Extract each check
        for check_id, check_data in self.checks_metadata.items():
            try:
                document = self.extract_check_data(check_id, check_data)
                self.extracted_data.append(document)
                logger.debug(f"Extracted data for check: {check_id}")
            except Exception as e:
                logger.error(f"Error extracting data for {check_id}: {e}")
                continue

        logger.info(f"Extracted data for {len(self.extracted_data)} checks")
        return self.extracted_data

    def generate_csv(self, output_file: str = None):
        """Generate CSV file from extracted data."""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"secure/gcp/opensearch_work/data/gcp/gcp_checks_extracted_{timestamp}.csv"

        output_path = PROJECT_ROOT / output_file
        output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Generating CSV file: {output_path}")

        # Define CSV columns (flattened structure for CSV)
        fieldnames = [
            # Basic check info
            "check_id",
            "provider",
            "module",
            "check_id_field",
            "check_title",
            "check_description",
            "check_service",
            "check_sub_service",
            "check_severity",
            "check_resource_type",
            "check_risk",
            "check_score",
            "check_type",
            "check_categories",
            "check_depends_on",
            "check_related_to",
            "check_related_url",
            "check_notes",

            # Remediation
            "remediation_cli",
            "remediation_terraform",
            "remediation_cloudformation",
            "remediation_other",
            "remediation_recommendation_text",
            "remediation_recommendation_url",

            # Finalized categories
            "finalized_main_category",
            "finalized_sub_category",
            "finalized_main",
            "finalized_sub",
        ]

        # Add benchmark columns
        for framework in self.gcp_frameworks:
            fieldnames.extend([
                f"benchmark_{framework}_exists",
                f"benchmark_{framework}_value",
                f"benchmark_{framework}_description"
            ])

        # Attributes summary (first attribute's key fields)
        fieldnames.extend([
            "attributes_section",
            "attributes_subsection",
            "attributes_profile",
            "attributes_assessment_status",
            "attributes_description",
            "attributes_impact_statement",
            "attributes_rationale_statement",
            "attributes_service",
            "attributes_count"
        ])

        # Timestamps
        fieldnames.extend([
            "created_at",
            "updated_at"
        ])

        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for doc in self.extracted_data:
                row = {}

                # Basic fields
                row["check_id"] = doc["check_id"]
                row["provider"] = doc["provider"]
                row["module"] = doc["module"]
                row["check_id_field"] = doc["check"]["id"]
                row["check_title"] = doc["check"]["title"]
                row["check_description"] = doc["check"]["description"]
                row["check_service"] = doc["check"]["service"]
                row["check_sub_service"] = doc["check"]["sub_service"]
                row["check_severity"] = doc["check"]["severity"]
                row["check_resource_type"] = doc["check"]["resource_type"]
                row["check_risk"] = doc["check"]["risk"]
                row["check_score"] = doc["check"]["score"]
                row["check_type"] = ", ".join(doc["check"]["type"]) if doc["check"]["type"] else ""
                row["check_categories"] = ", ".join(doc["check"]["categories"]) if doc["check"]["categories"] else ""
                row["check_depends_on"] = ", ".join(doc["check"]["depends_on"]) if doc["check"]["depends_on"] else ""
                row["check_related_to"] = ", ".join(doc["check"]["related_to"]) if doc["check"]["related_to"] else ""
                row["check_related_url"] = doc["check"]["related_url"]
                row["check_notes"] = doc["check"]["notes"]

                # Remediation
                row["remediation_cli"] = doc["remediation"]["cli"]
                row["remediation_terraform"] = doc["remediation"]["terraform"]
                row["remediation_cloudformation"] = doc["remediation"]["cloudformation"]
                row["remediation_other"] = doc["remediation"]["other"]
                row["remediation_recommendation_text"] = doc["remediation"]["recommendation_text"]
                row["remediation_recommendation_url"] = doc["remediation"]["recommendation_url"]

                # Finalized
                row["finalized_main_category"] = doc["finalized"]["main_category"]
                row["finalized_sub_category"] = doc["finalized"]["sub_category"]
                row["finalized_main"] = doc["finalized"]["main"]
                row["finalized_sub"] = doc["finalized"]["sub"]

                # Benchmarks
                for framework in self.gcp_frameworks:
                    benchmark = doc["benchmarks"].get(framework, {})
                    row[f"benchmark_{framework}_exists"] = benchmark.get("exists", False)
                    row[f"benchmark_{framework}_value"] = benchmark.get("value", "NA")
                    row[f"benchmark_{framework}_description"] = benchmark.get("description", "NA")

                # Attributes (first attribute)
                if doc["attributes"]:
                    first_attr = doc["attributes"][0]
                    row["attributes_section"] = first_attr.get("Section", "")
                    row["attributes_subsection"] = first_attr.get("SubSection", "")
                    row["attributes_profile"] = first_attr.get("Profile", "")
                    row["attributes_assessment_status"] = first_attr.get("AssessmentStatus", "")
                    row["attributes_description"] = first_attr.get("Description", "")
                    row["attributes_impact_statement"] = first_attr.get("ImpactStatement", "")
                    row["attributes_rationale_statement"] = first_attr.get("RationaleStatement", "")
                    row["attributes_service"] = first_attr.get("Service", "") or first_attr.get("GCPService", "")
                else:
                    row["attributes_section"] = ""
                    row["attributes_subsection"] = ""
                    row["attributes_profile"] = ""
                    row["attributes_assessment_status"] = ""
                    row["attributes_description"] = ""
                    row["attributes_impact_statement"] = ""
                    row["attributes_rationale_statement"] = ""
                    row["attributes_service"] = ""

                row["attributes_count"] = len(doc["attributes"])

                # Timestamps
                row["created_at"] = doc["created_at"]
                row["updated_at"] = doc["updated_at"]

                writer.writerow(row)

        logger.info(f"CSV file generated successfully: {output_path}")
        logger.info(f"Total rows: {len(self.extracted_data)}")
        logger.info(f"Total columns: {len(fieldnames)}")

        return str(output_path)


def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(description='Extract GCP check data for OpenSearch')
    parser.add_argument('--output', '-o', default=None,
                       help='Output CSV file path (default: auto-generated)')
    parser.add_argument('--prowler-root', default=None,
                       help='Path to Prowler root directory (default: auto-detect)')

    args = parser.parse_args()

    try:
        extractor = GCPDataExtractor(prowler_root=args.prowler_root)
        extractor.extract_all_data()
        csv_file = extractor.generate_csv(args.output)

        logger.info("=" * 80)
        logger.info("Extraction Summary")
        logger.info("=" * 80)
        logger.info(f"Total checks extracted: {len(extractor.extracted_data)}")
        logger.info(f"CSV file: {csv_file}")
        logger.info("=" * 80)

        print(f"\n✅ Success! CSV file generated: {csv_file}")
        print(f"📊 Total checks: {len(extractor.extracted_data)}")

    except Exception as e:
        logger.error(f"Extraction failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
