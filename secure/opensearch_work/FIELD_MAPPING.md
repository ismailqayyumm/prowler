# CSV to OpenSearch Index Field Mapping

## Overview
This document describes how CSV fields from `azure_checks_with_llm_risk_labels.csv` map to the OpenSearch index `prowler-checks-benchmarks`.

**Total CSV Columns:** 82
**Total Index Fields:** Nested structure with multiple objects

---

## Field Mapping Structure

### 1. Top-Level Fields (Direct Mapping)

| CSV Field | Index Field | Type | Notes |
|-----------|-------------|------|-------|
| `check_id` | `check_id` | text/keyword | Document ID |
| `provider` | `provider` | keyword | "azure" |
| `module` | `module` | keyword | Service name |
| `created_at` | `created_at` | date | ISO format |
| `updated_at` | `updated_at` | date | ISO format |

---

### 2. Check Object (Nested: `check.*`)

| CSV Field | Index Field | Type | Notes |
|-----------|-------------|------|-------|
| `check_id_field` | `check.id` | keyword | Check identifier |
| `check_title` | `check.title` | text | Check title |
| `check_description` | `check.description` | text | Full description |
| `check_service` | `check.service` | keyword | Service name |
| `check_sub_service` | `check.sub_service` | keyword | Sub-service |
| `check_severity` | `check.severity` | keyword | critical/high/medium/low/informational |
| `check_resource_type` | `check.resource_type` | keyword | Resource type |
| `check_risk` | `check.risk` | text | Risk description |
| `check_score` | `check.score` | float | Calculated risk score |
| `check_type` | `check.type` | keyword[] | Array (comma-separated in CSV) |
| `check_categories` | `check.categories` | keyword[] | Array (comma-separated in CSV) |
| `check_depends_on` | `check.depends_on` | keyword[] | Array (comma-separated in CSV) |
| `check_related_to` | `check.related_to` | keyword[] | Array (comma-separated in CSV) |
| `check_related_url` | `check.related_url` | keyword | URL |
| `check_notes` | `check.notes` | text | Additional notes |

---

### 3. Remediation Object (Nested: `remediation.*`)

| CSV Field | Index Field | Type | Notes |
|-----------|-------------|------|-------|
| `remediation_cli` | `remediation.cli` | text | CLI commands |
| `remediation_terraform` | `remediation.terraform` | text | Terraform code/URL |
| `remediation_cloudformation` | `remediation.cloudformation` | text | CloudFormation code/URL |
| `remediation_other` | `remediation.other` | text | Other remediation |
| `remediation_recommendation_text` | `remediation.recommendation_text` | text | Recommendation |
| `remediation_recommendation_url` | `remediation.recommendation_url` | keyword | Recommendation URL |

---

### 4. Finalized Object (Nested: `finalized.*`)

| CSV Field | Index Field | Type | Notes |
|-----------|-------------|------|-------|
| `finalized_main_category` | `finalized.main_category` | keyword | Main category |
| `finalized_sub_category` | `finalized.sub_category` | keyword | Sub category |
| `finalized_main` | `finalized.main` | keyword | Alias for main_category |
| `finalized_sub` | `finalized.sub` | keyword | Alias for sub_category |

---

### 5. Benchmarks Object (Nested: `benchmarks.{framework}.*`)

**Structure:** `benchmarks.{framework_name}.{field}`

For each Azure framework (12 total):
- `ccc_azure`
- `cis_2_0_azure`
- `cis_2_1_azure`
- `cis_3_0_azure`
- `cis_4_0_azure`
- `ens_rd2022_azure`
- `iso27001_2022_azure`
- `mitre_attack_azure`
- `nis2_azure`
- `pci_4_0_azure`
- `prowler_threatscore_azure`
- `soc2_azure`

| CSV Field Pattern | Index Field Pattern | Type | Notes |
|-------------------|---------------------|------|-------|
| `benchmark_{framework}_exists` | `benchmarks.{framework}.exists` | boolean | Framework mapping exists |
| `benchmark_{framework}_value` | `benchmarks.{framework}.value` | keyword | Requirement ID or "NA" |
| `benchmark_{framework}_description` | `benchmarks.{framework}.description` | text | Requirement description |

**Example:**
- CSV: `benchmark_cis_4_0_azure_exists` → Index: `benchmarks.cis_4_0_azure.exists`
- CSV: `benchmark_cis_4_0_azure_value` → Index: `benchmarks.cis_4_0_azure.value`
- CSV: `benchmark_cis_4_0_azure_description` → Index: `benchmarks.cis_4_0_azure.description`

---

### 6. Attributes Array (Nested: `attributes[]`)

**Note:** CSV only contains the first attribute, but index supports an array.

| CSV Field | Index Field | Type | Notes |
|-----------|-------------|------|-------|
| `attributes_section` | `attributes[].Section` | text | First attribute only |
| `attributes_subsection` | `attributes[].SubSection` | text | First attribute only |
| `attributes_profile` | `attributes[].Profile` | text | First attribute only |
| `attributes_assessment_status` | `attributes[].AssessmentStatus` | text | First attribute only |
| `attributes_description` | `attributes[].Description` | text | First attribute only |
| `attributes_impact_statement` | `attributes[].ImpactStatement` | text | First attribute only |
| `attributes_rationale_statement` | `attributes[].RationaleStatement` | text | First attribute only |
| `attributes_service` | `attributes[].Service` | keyword | First attribute only |
| `attributes_count` | N/A | N/A | Metadata (not indexed) |

**Note:** The index supports multiple attributes in an array, but CSV only has the first one flattened.

---

### 7. LLM Object (Nested: `llm.*`)

| CSV Field | Index Field | Type | Notes |
|-----------|-------------|------|-------|
| `mitre_technique_id` | `llm.mitre_analysis.technique_id` | keyword | e.g., "T1530" |
| `mitre_tactic` | `llm.mitre_analysis.tactics` | keyword[] | Array (single value in CSV) |
| `mitre_technique_name` | `llm.mitre_analysis.technique_name` | text | Technique name |
| `risk_main_category` | `llm.risk_analysis.main_category` | keyword | MITRE tactic |
| `risk_sub_category` | `llm.risk_analysis.sub_categories` | keyword[] | Array (single value in CSV) |
| `llm_reasoning` | `llm.risk_analysis.categorization_reason` | text | Explanation |
| `llm_confidence` | `llm.risk_analysis.categorization_confidence` | integer | Convert 0.0-1.0 to 0-100 |

**Additional LLM Fields (to be set):**
- `llm.mitre_analysis.confidence` → Same as categorization_confidence
- `llm.mitre_analysis.reason` → Same as categorization_reason
- `llm.overall_confidence` → Same as categorization_confidence
- `llm.model_used` → "claude-3-7-sonnet"
- `llm.analysis_timestamp` → Current timestamp

---

## Data Transformations Required

### 1. Array Fields
CSV fields that are comma-separated need to be split into arrays:
- `check_type` → Split by comma
- `check_categories` → Split by comma
- `check_depends_on` → Split by comma
- `check_related_to` → Split by comma

### 2. Boolean Fields
- `benchmark_*_exists` → Convert "True"/"False" strings to boolean

### 3. Date Fields
- `created_at`, `updated_at` → Parse ISO format strings

### 4. Numeric Fields
- `check_score` → Convert to float
- `llm_confidence` → Convert 0.0-1.0 to 0-100 integer

### 5. Empty/NA Values
- Empty strings → Omit field or use null
- "NA" values → Omit field or use null

### 6. Nested Objects
Build nested structure:
- `check` object
- `remediation` object
- `finalized` object
- `benchmarks` object (dynamic based on framework names)
- `attributes` array (single object from CSV)
- `llm` object

---

## Document ID Strategy

**Recommended:** Use `check_id` as the document ID (`_id` field in OpenSearch)

This ensures:
- Unique documents per check
- Easy updates (same ID = update existing document)
- No duplicates

---

## Example Document Structure

```json
{
  "_id": "storage_blob_public_access_level_is_disabled",
  "_source": {
    "check_id": "storage_blob_public_access_level_is_disabled",
    "provider": "azure",
    "module": "storage",
    "check": {
      "id": "storage_blob_public_access_level_is_disabled",
      "title": "Ensure that the 'Public access level' is set to 'Private'...",
      "description": "...",
      "service": "storage",
      "severity": "medium",
      "risk": "A user that accesses blob containers anonymously...",
      "score": 4.5,
      "categories": ["internet-exposed"],
      "type": ["Data Protection"]
    },
    "remediation": {
      "terraform": "https://...",
      "recommendation_text": "Set 'Public access level' to 'Private'"
    },
    "finalized": {
      "main_category": "Data Exposure",
      "sub_category": "Public Access"
    },
    "benchmarks": {
      "cis_4_0_azure": {
        "exists": true,
        "value": "2.2.1.1",
        "description": "Ensure public network access is Disabled"
      }
    },
    "attributes": [{
      "Section": "2 Common Reference Recommendations",
      "SubSection": "2.2 Networking",
      "Profile": "Level 1",
      "ImpactStatement": "Disabling public network access restricts access..."
    }],
    "llm": {
      "mitre_analysis": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactics": ["Collection"],
        "confidence": 92,
        "reason": "Public blob containers allow..."
      },
      "risk_analysis": {
        "main_category": "Collection",
        "sub_categories": ["Data from Cloud Storage"],
        "categorization_reason": "Public blob containers allow...",
        "categorization_confidence": 92
      },
      "overall_confidence": 92,
      "model_used": "claude-3-7-sonnet",
      "analysis_timestamp": "2026-01-20T22:00:00Z"
    },
    "created_at": "2026-01-20T21:45:36Z",
    "updated_at": "2026-01-20T22:00:00Z"
  }
}
```

---

## Summary

- **Total CSV Columns:** 82
- **Top-level Index Fields:** 5
- **Nested Objects:** 6 (check, remediation, finalized, benchmarks, attributes, llm)
- **Array Fields:** 4 (check.type, check.categories, check.depends_on, check.related_to)
- **Dynamic Fields:** 12 frameworks × 3 fields = 36 benchmark fields
