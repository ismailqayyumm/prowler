#!/usr/bin/env python3
"""
Extract MITRE ATT&CK techniques from OpenSearch index.

This script:
1. Connects to OpenSearch
2. Extracts parent techniques only (default) or includes sub-techniques
3. Organizes by tactic
4. Saves to JSON for further processing

Note: Sub-techniques always have a parent, so filtering to parents only
      ensures we have complete coverage without redundancy.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List
from dotenv import load_dotenv
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    from opensearchpy import OpenSearch
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False
    logger.error("opensearch-py not installed. Install with: pip install opensearch-py")


def extract_techniques_from_opensearch(
    opensearch_host: str,
    index_name: str = "mitre-attack-techniques",
    include_subtechniques: bool = False,
    username: str = None,
    password: str = None
) -> List[Dict]:
    """
    Extract MITRE ATT&CK techniques from OpenSearch index.

    By default, extracts parent techniques only (excludes sub-techniques).
    Since sub-techniques always have a parent, this ensures complete coverage
    without redundancy.

    Args:
        opensearch_host: OpenSearch host URL (e.g., "https://localhost:9200")
        index_name: Index name containing techniques
        include_subtechniques: Whether to include sub-techniques (default: False)
        username: Optional username for authentication
        password: Optional password for authentication

    Returns:
        List of technique documents with fields:
        - technique_id: Document ID (e.g., "T1608")
        - name: Technique name
        - description: Technique description
        - tactics: List of tactics this technique belongs to
        - is_subtechnique: Boolean (always False when include_subtechniques=False)
        - parent_technique_id: If sub-technique, the parent ID
        - parent_technique_name: If sub-technique, the parent name
    """
    if not OPENSEARCH_AVAILABLE:
        raise ImportError("opensearch-py is required. Install with: pip install opensearch-py")

    logger.info(f"Connecting to OpenSearch at {opensearch_host}")
    logger.info(f"Index: {index_name}")
    logger.info(f"Include sub-techniques: {include_subtechniques}")

    # Initialize OpenSearch client
    auth = None
    if username and password:
        auth = (username, password)
        logger.info("Using authentication")

    client = OpenSearch(
        hosts=[opensearch_host],
        http_auth=auth,
        http_compress=True,
        use_ssl=True,
        verify_certs=False,  # Adjust based on your setup
        ssl_show_warn=False
    )

    # Test connection
    try:
        info = client.info()
        logger.info(f"Connected to OpenSearch cluster: {info.get('cluster_name', 'unknown')}")
    except Exception as e:
        logger.error(f"Failed to connect to OpenSearch: {e}")
        raise

    # Query all techniques
    query = {
        "query": {
            "match_all": {}
        },
        "size": 10000  # Adjust if you have more techniques
    }

    if not include_subtechniques:
        query["query"] = {
            "bool": {
                "must_not": {
                    "term": {"is_subtechnique": True}
                }
            }
        }
        logger.info("Filtering out sub-techniques")

    logger.info("Fetching techniques from OpenSearch...")

    try:
        response = client.search(index=index_name, body=query, scroll='2m')
    except Exception as e:
        logger.error(f"Failed to search index: {e}")
        raise

    techniques = []
    scroll_id = response.get('_scroll_id')
    total_hits = response['hits']['total']

    # Handle different total formats (ES 7.x vs 6.x)
    if isinstance(total_hits, dict):
        total_count = total_hits.get('value', 0)
    else:
        total_count = total_hits

    logger.info(f"Found {total_count} techniques")

    # Process first batch
    for hit in response['hits']['hits']:
        doc = hit['_source'].copy()
        doc['technique_id'] = hit['_id']  # Document ID is technique_id
        # Ensure 'name' field is extracted (technique name)
        if 'name' not in doc and 'technique_name' in doc:
            doc['name'] = doc['technique_name']
        elif 'name' not in doc:
            logger.warning(f"Technique {hit['_id']} missing 'name' field")
        techniques.append(doc)

    logger.info(f"Processed {len(techniques)} techniques...")

    # Scroll through remaining results
    while scroll_id and len(response['hits']['hits']) > 0:
        try:
            response = client.scroll(scroll_id=scroll_id, scroll='2m')
            scroll_id = response.get('_scroll_id')

            for hit in response['hits']['hits']:
                doc = hit['_source'].copy()
                doc['technique_id'] = hit['_id']
                # Ensure 'name' field is extracted (technique name)
                if 'name' not in doc and 'technique_name' in doc:
                    doc['name'] = doc['technique_name']
                elif 'name' not in doc:
                    logger.warning(f"Technique {hit['_id']} missing 'name' field")
                techniques.append(doc)

            if len(techniques) % 100 == 0:
                logger.info(f"Processed {len(techniques)} techniques...")

        except Exception as e:
            logger.warning(f"Error during scroll: {e}")
            break

    logger.info(f"Extracted {len(techniques)} techniques from OpenSearch")
    return techniques


def organize_by_tactic(techniques: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Organize techniques by tactic.

    A technique can belong to multiple tactics, so it will appear in each.

    Args:
        techniques: List of technique documents

    Returns:
        Dict mapping tactic name -> list of techniques
    """
    tactic_to_techniques = {}

    for technique in techniques:
        technique_id = technique.get('technique_id', '')
        name = technique.get('name', '')
        description = technique.get('description', '')
        tactics = technique.get('tactics', [])
        is_subtechnique = technique.get('is_subtechnique', False)
        parent_technique_id = technique.get('parent_technique_id', '')
        parent_technique_name = technique.get('parent_technique_name', '')

        # Create technique summary
        tech_summary = {
            'technique_id': technique_id,
            'name': name,
            'description': description[:1000] if description else '',  # Truncate for readability
            'is_subtechnique': is_subtechnique,
            'parent_technique_id': parent_technique_id,
            'parent_technique_name': parent_technique_name
        }

        # Add to all tactics it belongs to
        if tactics:
            # Handle both list and single value
            if isinstance(tactics, str):
                tactics = [tactics]

            for tactic in tactics:
                if tactic not in tactic_to_techniques:
                    tactic_to_techniques[tactic] = []
                tactic_to_techniques[tactic].append(tech_summary)
        else:
            # If no tactics, add to "Unknown"
            if "Unknown" not in tactic_to_techniques:
                tactic_to_techniques["Unknown"] = []
            tactic_to_techniques["Unknown"].append(tech_summary)

    logger.info(f"Organized techniques into {len(tactic_to_techniques)} tactics")
    for tactic, techs in sorted(tactic_to_techniques.items()):
        logger.info(f"  {tactic}: {len(techs)} techniques")

    return tactic_to_techniques


def save_techniques_json(
    techniques: List[Dict],
    tactic_to_techniques: Dict[str, List[Dict]],
    output_path: str,
    include_subtechniques: bool
):
    """
    Save extracted techniques to JSON file.

    Args:
        techniques: Full list of techniques
        tactic_to_techniques: Techniques organized by tactic
        output_path: Path to save JSON
        include_subtechniques: Whether sub-techniques were included
    """
    logger.info(f"Saving techniques to {output_path}")

    # Count statistics
    main_techniques = [t for t in techniques if not t.get('is_subtechnique', False)]
    sub_techniques = [t for t in techniques if t.get('is_subtechnique', False)]

    output = {
        "metadata": {
            "total_techniques": len(techniques),
            "main_techniques": len(main_techniques),
            "sub_techniques": len(sub_techniques),
            "include_subtechniques": include_subtechniques,
            "total_tactics": len(tactic_to_techniques),
            "tactics": sorted(tactic_to_techniques.keys())
        },
        "techniques_by_tactic": tactic_to_techniques,
        "all_techniques": techniques  # Full list for reference
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    logger.info(f"Saved {output_path}")

    # Print summary
    print("\n" + "="*80)
    print("Extraction Summary")
    print("="*80)
    print(f"Total techniques: {len(techniques)}")
    print(f"  Main techniques: {len(main_techniques)}")
    print(f"  Sub-techniques: {len(sub_techniques)}")
    print(f"Tactics: {len(tactic_to_techniques)}")
    print("\nTechniques per tactic:")
    for tactic, techs in sorted(tactic_to_techniques.items()):
        print(f"  {tactic}: {len(techs)}")
    print("="*80)


def main():
    """Main execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract MITRE ATT&CK techniques from OpenSearch"
    )
    parser.add_argument(
        "--include-subtechniques",
        action="store_true",
        help="Include sub-techniques (default: exclude, use parent techniques only)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON file path (default: data/mappings/techniques_extracted.json)"
    )
    args = parser.parse_args()

    load_dotenv()

    # Configuration
    OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
    OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT", "9200")
    OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "mitre-attack-techniques")
    OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
    OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")
    INCLUDE_SUBTECHNIQUES = args.include_subtechniques  # Default: False (parents only)

    # Construct full URL if needed
    if not OPENSEARCH_HOST.startswith("http"):
        # Determine protocol based on port
        protocol = "https" if OPENSEARCH_PORT == "443" else "http"
        opensearch_url = f"{protocol}://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
    else:
        opensearch_url = OPENSEARCH_HOST

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_dir = Path(__file__).parent.parent / "data" / "mappings"
        output_dir.mkdir(parents=True, exist_ok=True)
        suffix = "with_subtechniques" if INCLUDE_SUBTECHNIQUES else "parents_only"
        output_path = output_dir / f"techniques_extracted_{suffix}.json"

    # Step 1: Extract from OpenSearch
    techniques = extract_techniques_from_opensearch(
        opensearch_host=opensearch_url,
        index_name=OPENSEARCH_INDEX,
        include_subtechniques=INCLUDE_SUBTECHNIQUES,
        username=OPENSEARCH_USER,
        password=OPENSEARCH_PASSWORD
    )

    # Step 2: Organize by tactic
    tactic_to_techniques = organize_by_tactic(techniques)

    # Step 3: Save to JSON
    save_techniques_json(
        techniques=techniques,
        tactic_to_techniques=tactic_to_techniques,
        output_path=str(output_path),
        include_subtechniques=INCLUDE_SUBTECHNIQUES
    )

    print(f"\n✓ Complete! Output saved to: {output_path}")


if __name__ == "__main__":
    main()
