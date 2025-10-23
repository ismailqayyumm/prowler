#!/usr/bin/env python3
"""
Kubernetes Services Data Extraction Script for OpenSearch

This script extracts data from Kubernetes service JSON metadata files
and transforms them into OpenSearch-compatible documents for the
prowler-checks-benchmarks index.

Author: Prowler Team
Date: 2024
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('kubernetes_extraction.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class KubernetesCheckExtractor:
    """Extracts and transforms Kubernetes check data for OpenSearch indexing."""
    
    def __init__(self, services_path: str = "prowler/providers/kubernetes/services"):
        self.services_path = Path(services_path)
        self.extracted_checks = []
        self.stats = {
            'total_files': 0,
            'successful_extractions': 0,
            'failed_extractions': 0,
            'services_processed': set()
        }
    
    def find_json_files(self) -> List[Path]:
        """Find all JSON metadata files in the services directory."""
        json_files = []
        for root, dirs, files in os.walk(self.services_path):
            for file in files:
                if file.endswith('.metadata.json'):
                    json_files.append(Path(root) / file)
        return json_files
    
    def extract_check_data(self, json_file: Path) -> Optional[Dict[str, Any]]:
        """Extract and transform a single check's data."""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                check_data = json.load(f)
            
            # Transform to OpenSearch format
            opensearch_doc = self.transform_to_opensearch(check_data, json_file)
            return opensearch_doc
            
        except Exception as e:
            logger.error(f"Failed to extract data from {json_file}: {str(e)}")
            self.stats['failed_extractions'] += 1
            return None
    
    def transform_to_opensearch(self, check_data: Dict[str, Any], file_path: Path) -> Dict[str, Any]:
        """Transform Kubernetes check data to OpenSearch document format."""
        
        # Extract service name from file path
        service_name = file_path.parts[-3] if len(file_path.parts) >= 3 else "unknown"
        self.stats['services_processed'].add(service_name)
        
        # Map Kubernetes check data to OpenSearch structure
        opensearch_doc = {
            # Core check information
            "check": {
                "id": check_data.get("CheckID") or "NA",
                "title": check_data.get("CheckTitle") or "NA",
                "description": check_data.get("Description") or "NA",
                "service": check_data.get("ServiceName") or service_name or "NA",
                "sub_service": check_data.get("SubServiceName") or "NA",
                "severity": check_data.get("Severity") or "NA",
                "resource_type": check_data.get("ResourceType") or "NA",
                "categories": check_data.get("Categories") or ["NA"],
                "risk": check_data.get("Risk") or "NA",
                "related_url": check_data.get("RelatedUrl") or "NA",
                "notes": check_data.get("Notes") or "NA",
                "depends_on": check_data.get("DependsOn") or ["NA"],
                "related_to": check_data.get("RelatedTo") or ["NA"],
                "type": check_data.get("CheckType") or ["NA"],
                "score": self.calculate_severity_score(check_data.get("Severity", ""))
            },
            
            # Provider and framework information
            "provider": "Kubernetes",
            "framework": self.determine_framework(check_data),
            "framework_name": self.get_framework_name(check_data),
            "framework_version": self.get_framework_version(check_data),
            
            # Check ID for indexing
            "check_id": check_data.get("CheckID") or "NA",
            
            # Remediation information
            "remediation": {
                "cli": check_data.get("Remediation", {}).get("Code", {}).get("CLI") or "NA",
                "terraform": check_data.get("Remediation", {}).get("Code", {}).get("Terraform") or "NA",
                "cloudformation": check_data.get("Remediation", {}).get("Code", {}).get("NativeIaC") or "NA",
                "other": check_data.get("Remediation", {}).get("Code", {}).get("Other") or "NA",
                "recommendation_text": check_data.get("Remediation", {}).get("Recommendation", {}).get("Text") or "NA",
                "recommendation_url": check_data.get("Remediation", {}).get("Recommendation", {}).get("Url") or "NA"
            },
            
            # Timestamps
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
            
            # Additional metadata
            "module": "kubernetes",
            "checks": [check_data.get("CheckID") or "NA"],
            
            # Framework-specific attributes (nested structure for compliance)
            "attributes": self.build_attributes(check_data),
            
            # Benchmarks mapping (for compliance frameworks)
            "benchmarks": self.build_benchmarks(check_data)
        }
        
        return opensearch_doc
    
    def calculate_severity_score(self, severity: str) -> float:
        """Calculate numeric score based on severity."""
        if not severity or severity == "NA":
            return 5.0  # Default to medium severity
        
        severity_scores = {
            "critical": 9,
            "high": 7,
            "medium": 4,
            "low": 1,
        }
        return severity_scores.get(severity.lower(), 5.0)
    
    def determine_framework(self, check_data: Dict[str, Any]) -> str:
        """Determine the primary compliance framework for this check."""
        # Based on the service and check type, determine the framework
        service = check_data.get("ServiceName", "").lower()
        categories = check_data.get("Categories", [])
        
        if "container-security" in categories or service == "core":
            return "cis_kubernetes"
        elif "encryption" in categories or service in ["etcd", "apiserver"]:
            return "cis_kubernetes"
        elif "trustboundaries" in categories or service == "rbac":
            return "cis_kubernetes"
        else:
            return "cis_kubernetes"  # Default to CIS Kubernetes
    
    def get_framework_name(self, check_data: Dict[str, Any]) -> str:
        """Get the human-readable framework name."""
        return "CIS Kubernetes Benchmark"
    
    def get_framework_version(self, check_data: Dict[str, Any]) -> str:
        """Get the framework version."""
        return "1.11"
    
    def build_attributes(self, check_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build attributes array for compliance mapping."""
        categories = check_data.get("Categories", [])
        category_str = ", ".join(categories) if categories else "NA"
        
        return [{
            "Description": check_data.get("Description") or "NA",
            "Category": category_str,
            "Service": check_data.get("ServiceName") or "NA",
            "Section": f"Kubernetes {(check_data.get('ServiceName') or 'NA').title()} Security",
            "SubSection": check_data.get("CheckTitle") or "NA",
            "Profile": "Level 1" if check_data.get("Severity") == "high" else "Level 2",
            "AssessmentStatus": "Automated",
            "RationaleStatement": check_data.get("Risk") or "NA",
            "ImpactStatement": "Security risk if not implemented",
            "RemediationProcedure": check_data.get("Remediation", {}).get("Recommendation", {}).get("Text") or "NA",
            "AuditProcedure": f"Run Prowler check: {check_data.get('CheckID') or 'NA'}",
            "References": check_data.get("RelatedUrl") or "NA",
            "AdditionalInformation": check_data.get("Notes") or "NA",
            "DefaultValue": "Not configured by default"
        }]
    
    def build_benchmarks(self, check_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build benchmarks mapping for compliance frameworks."""
        # Only use actual benchmarks data from the metadata, don't generate fake data
        benchmarks = check_data.get("Benchmarks", {})
        
        if not benchmarks:
            # If no benchmarks data exists, return NA for all frameworks
            return {
                "cis_1_11_kubernetes": {
                    "exists": False,
                    "value": "NA",
                    "description": "NA"
                },
                "pci_4_0_kubernetes": {
                    "exists": False,
                    "value": "NA", 
                    "description": "NA"
                },
                "iso27001_2022_kubernetes": {
                    "exists": False,
                    "value": "NA",
                    "description": "NA"
                }
            }
        
        # Use actual benchmarks data if it exists
        return benchmarks
    
    def extract_all_checks(self) -> List[Dict[str, Any]]:
        """Extract data from all Kubernetes check files."""
        logger.info("Starting Kubernetes checks extraction...")
        
        json_files = self.find_json_files()
        self.stats['total_files'] = len(json_files)
        
        logger.info(f"Found {len(json_files)} JSON metadata files")
        
        for json_file in json_files:
            logger.info(f"Processing: {json_file}")
            check_data = self.extract_check_data(json_file)
            
            if check_data:
                self.extracted_checks.append(check_data)
                self.stats['successful_extractions'] += 1
            else:
                logger.warning(f"Failed to extract data from: {json_file}")
        
        logger.info("Extraction completed!")
        self.print_stats()
        
        return self.extracted_checks
    
    def print_stats(self):
        """Print extraction statistics."""
        logger.info("=== EXTRACTION STATISTICS ===")
        logger.info(f"Total files processed: {self.stats['total_files']}")
        logger.info(f"Successful extractions: {self.stats['successful_extractions']}")
        logger.info(f"Failed extractions: {self.stats['failed_extractions']}")
        logger.info(f"Services processed: {', '.join(sorted(self.stats['services_processed']))}")
        logger.info(f"Success rate: {(self.stats['successful_extractions'] / self.stats['total_files'] * 100):.1f}%")
    
    def save_to_file(self, output_file: str = "kubernetes_checks_opensearch.json"):
        """Save extracted data to JSON file."""
        output_data = {
            "metadata": {
                "extraction_timestamp": datetime.utcnow().isoformat() + "Z",
                "total_checks": len(self.extracted_checks),
                "services_processed": list(self.stats['services_processed']),
                "extraction_stats": {
                    'total_files': self.stats['total_files'],
                    'successful_extractions': self.stats['successful_extractions'],
                    'failed_extractions': self.stats['failed_extractions'],
                    'services_processed': list(self.stats['services_processed'])
                }
            },
            "checks": self.extracted_checks
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Extracted data saved to: {output_file}")
    
    def generate_bulk_index_format(self, output_file: str = "kubernetes_checks_bulk.json"):
        """Generate OpenSearch bulk index format."""
        bulk_actions = []
        
        for check in self.extracted_checks:
            # Index action
            index_action = {
                "index": {
                    "_index": "prowler-checks-benchmarks",
                    "_id": check["check"]["id"]
                }
            }
            bulk_actions.append(index_action)
            bulk_actions.append(check)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for action in bulk_actions:
                f.write(json.dumps(action) + '\n')
        
        logger.info(f"Bulk index format saved to: {output_file}")
        logger.info(f"Total documents for indexing: {len(self.extracted_checks)}")

def main():
    """Main execution function."""
    try:
        # Initialize extractor
        extractor = KubernetesCheckExtractor()
        
        # Extract all checks
        checks = extractor.extract_all_checks()
        
        if not checks:
            logger.error("No checks were extracted. Exiting.")
            sys.exit(1)
        
        # Save results
        extractor.save_to_file()
        extractor.generate_bulk_index_format()
        
        logger.info("Kubernetes checks extraction completed successfully!")
        
    except Exception as e:
        logger.error(f"Extraction failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()