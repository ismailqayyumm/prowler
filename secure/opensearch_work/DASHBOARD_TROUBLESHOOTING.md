# OpenSearch Dashboard Troubleshooting Guide

## Status: Documents ARE Uploaded ✅

**Verification Results:**
- ✅ 165 Azure documents successfully uploaded to `prowler-checks-benchmarks`
- ✅ Documents are queryable via API
- ✅ All documents have correct structure
- ✅ Index refreshed and ready

## If Documents Don't Show in Dashboard

### 1. Check Index Selection
- Make sure you're viewing the correct index: **`prowler-checks-benchmarks`**
- Dashboard might default to a different index

### 2. Remove Time Range Filters
- OpenSearch Dashboards often apply time range filters by default
- Check the time picker in the top right
- Set it to "Last 7 days" or "All time"
- Or remove any `@timestamp` or `created_at` filters

### 3. Add Provider Filter
- In the search bar, try: `provider:azure`
- Or use Discover/Dev Tools with query:
  ```json
  {
    "query": {
      "term": {
        "provider": "azure"
      }
    }
  }
  ```

### 4. Refresh the Dashboard
- Press `F5` or click the refresh button
- Sometimes dashboards cache query results

### 5. Check Index Pattern
- If using Index Patterns, make sure `prowler-checks-benchmarks` is included
- Go to: Stack Management → Index Patterns
- Verify the pattern matches your index

### 6. Verify Permissions
- Ensure your user has read permissions for the index
- Check role-based access control (RBAC) settings

### 7. Direct API Query
Test directly via API to confirm documents are accessible:

```bash
# Using curl
curl -X GET "https://opensearch-stg.secure.com:443/prowler-checks-benchmarks/_search" \
  -u "admin:password" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "term": {
        "provider": "azure"
      }
    },
    "size": 10
  }'
```

### 8. Check Document Structure
Documents have this structure:
```json
{
  "check_id": "storage_blob_public_access_level_is_disabled",
  "provider": "azure",
  "module": "storage",
  "check": { ... },
  "remediation": { ... },
  "benchmarks": { ... },
  "attributes": [ ... ],
  "created_at": "2026-01-20T22:42:29.486149",
  "updated_at": "2026-01-20T22:42:29.486149"
}
```

### 9. Common Dashboard Issues

**Issue: "No results found"**
- Solution: Remove all filters and try `provider:azure`

**Issue: "Index not found"**
- Solution: Verify index name is exactly `prowler-checks-benchmarks`

**Issue: "Permission denied"**
- Solution: Check user permissions for the index

**Issue: Documents show but fields are empty**
- Solution: This is expected - LLM data hasn't been added yet

## Quick Verification Commands

### Using the verification script:
```bash
cd opensearch_work/scripts
python verify_upload.py
```

### Using the query script:
```bash
python query_azure_checks.py
```

## Next Steps

1. **If documents still don't show:**
   - Check dashboard logs for errors
   - Try accessing via Dev Tools in OpenSearch Dashboards
   - Verify network connectivity to OpenSearch

2. **To add LLM data:**
   ```bash
   cd LLM_risk_labelling
   python azure_mapper.py  # Generate LLM labels
   python merge_azure_results.py  # Merge with CSV
   cd ../opensearch_work/scripts
   python upload_azure_checks.py  # Re-upload with LLM data
   ```

## Document Count Verification

- **Total in index:** 9,394 documents
- **Azure documents:** 165
- **Upload status:** ✅ All successful (0 errors)
- **Last upload:** 2026-01-20T22:42:29
