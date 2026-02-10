#!/usr/bin/env python3
"""
Extract CVE data with existing MITRE mappings and prepare for LLM risk labeling.
Uses existing MITRE data from CSV, validates against techniques database.
"""

import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
SOURCE_CSV = PROJECT_ROOT / "azure-resource-data.csv"
OUTPUT_DIR = PROJECT_ROOT / "secure" / "cve" / "opensearch_work" / "data" / "cve"
TECHNIQUES_DB = PROJECT_ROOT / "secure" / "shared" / "techniques_extracted_parents_only.json"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_techniques_database() -> Dict[str, Dict]:
    """Load MITRE ATT&CK techniques database."""
    if not TECHNIQUES_DB.exists():
        raise FileNotFoundError(f"Techniques database not found: {TECHNIQUES_DB}")

    with open(TECHNIQUES_DB, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Build lookup dictionary: technique_id -> technique_info
    technique_lookup = {}

    for tactic, techniques in data.get('techniques_by_tactic', {}).items():
        for tech in techniques:
            tech_id = tech['technique_id']
            if tech_id not in technique_lookup:
                technique_lookup[tech_id] = {
                    'name': tech['name'],
                    'tactics': [tactic],
                    'description': tech.get('description', '')
                }
            else:
                # Technique can belong to multiple tactics
                technique_lookup[tech_id]['tactics'].append(tactic)

    print(f"✓ Loaded {len(technique_lookup)} parent techniques from database")
    return technique_lookup

def extract_parent_technique_id(technique_id: str) -> str:
    """Extract parent technique ID from sub-technique (e.g., T1562.001 -> T1562)."""
    if '.' in technique_id:
        return technique_id.split('.')[0]
    return technique_id

def lookup_technique(technique_id: str, technique_lookup: Dict) -> Optional[Dict]:
    """Lookup technique in database, try parent if sub-technique."""
    # Try exact match first
    if technique_id in technique_lookup:
        return technique_lookup[technique_id]

    # Try parent technique
    parent_id = extract_parent_technique_id(technique_id)
    if parent_id in technique_lookup:
        return technique_lookup[parent_id]

    return None

def extract_cve_data(technique_lookup: Dict) -> Dict[str, Dict]:
    """Extract unique CVE data with aggregated MITRE mappings."""
    if not SOURCE_CSV.exists():
        raise FileNotFoundError(f"Source CSV not found: {SOURCE_CSV}")

    cve_data = {}

    with open(SOURCE_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get('cve_id', '').strip()
            if not cve_id:
                continue

            if cve_id not in cve_data:
                cve_data[cve_id] = {
                    'cve_id': cve_id,
                    'provider': row.get('provider', 'azure'),
                    'mitre_mappings': {},  # technique_id -> full info
                    'resources': set()
                }

            # Collect MITRE mappings with validation
            technique_id = row.get('llm_technique_id', '').strip()

            if technique_id and technique_id != 'NA':
                # Always use parent technique ID (remove sub-technique)
                parent_technique_id = extract_parent_technique_id(technique_id)

                # Lookup in database
                tech_info = lookup_technique(parent_technique_id, technique_lookup)

                if tech_info:
                    # Use database name and tactics with parent technique ID
                    if parent_technique_id not in cve_data[cve_id]['mitre_mappings']:
                        cve_data[cve_id]['mitre_mappings'][parent_technique_id] = {
                            'technique_id': parent_technique_id,
                            'name': tech_info['name'],
                            'tactics': tech_info['tactics'],
                            'from_database': True
                        }
                        if technique_id != parent_technique_id:
                            print(f"  → {cve_id}: Mapped sub-technique {technique_id} to parent {parent_technique_id}")
                else:
                    # Fallback to CSV data if not in database
                    technique = row.get('llm_technique', '').strip()
                    tactic = row.get('llm_tactic', '').strip()

                    if parent_technique_id not in cve_data[cve_id]['mitre_mappings']:
                        cve_data[cve_id]['mitre_mappings'][parent_technique_id] = {
                            'technique_id': parent_technique_id,
                            'name': technique,
                            'tactics': [tactic] if tactic else [],
                            'from_database': False
                        }
                        print(f"  ⚠️  {cve_id}: Technique {parent_technique_id} not found in database, using CSV data")

            # Collect resources
            resource = row.get('resource_name', '').strip()
            if resource:
                cve_data[cve_id]['resources'].add(resource)

    print(f"✓ Extracted {len(cve_data)} unique CVEs")

    # Convert sets to lists for export
    for cve_id, data in cve_data.items():
        data['resources'] = list(data['resources'])
        mappings_count = len(data['mitre_mappings'])
        validated_count = sum(1 for m in data['mitre_mappings'].values() if m['from_database'])
        print(f"  - {cve_id}: {mappings_count} MITRE mappings ({validated_count} validated), {len(data['resources'])} resources")

    return cve_data

def format_tactic_title_case(tactic: str) -> str:
    """Convert tactic from lowercase-with-hyphens to Title Case."""
    if not tactic:
        return ''
    # Replace hyphens with spaces and title case
    return tactic.replace('-', ' ').title()

def select_primary_mitre(mappings: Dict) -> tuple:
    """Select the primary MITRE mapping from multiple options."""
    if not mappings:
        return ('', '', '')

    # Convert dict to list
    mapping_list = list(mappings.values())

    # Prefer mappings from database
    from_db = [m for m in mapping_list if m.get('from_database')]
    if from_db:
        mapping = from_db[0]
    else:
        mapping = mapping_list[0]

    # Return technique_id, name, primary tactic (in Title Case)
    technique_id = mapping['technique_id']
    name = mapping['name']
    tactics = mapping.get('tactics', [])
    primary_tactic = format_tactic_title_case(tactics[0]) if tactics else ''

    return (technique_id, name, primary_tactic)

def export_to_csv(cve_data: Dict[str, Dict]) -> Path:
    """Export CVE data to CSV for LLM processing."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = OUTPUT_DIR / f"cve_extracted_{timestamp}.csv"

    fieldnames = [
        'cve_id',
        'provider',
        'mitre_technique_id',
        'mitre_technique_name',
        'mitre_tactic',
        'resource_count',
        'mapping_count'
    ]

    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for cve_id, data in sorted(cve_data.items()):
            # Select primary MITRE mapping
            primary = select_primary_mitre(data['mitre_mappings'])

            row = {
                'cve_id': cve_id,
                'provider': data['provider'],
                'mitre_technique_id': primary[0],
                'mitre_technique_name': primary[1],
                'mitre_tactic': primary[2],
                'resource_count': len(data['resources']),
                'mapping_count': len(data['mitre_mappings'])
            }
            writer.writerow(row)

    print(f"\n✓ Exported to {output_file}")
    return output_file

def main():
    """Main execution flow."""
    print("="*80)
    print("CVE Data Extractor (with MITRE ATT&CK database validation)")
    print("="*80)

    # Load techniques database
    technique_lookup = load_techniques_database()

    # Extract CVE data
    cve_data = extract_cve_data(technique_lookup)

    # Export to CSV
    output_file = export_to_csv(cve_data)

    print("\n" + "="*80)
    print(f"✓ Extraction complete! Output: {output_file.name}")
    print("="*80)

if __name__ == "__main__":
    main()
