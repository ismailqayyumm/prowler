# Fix: Documents Not Showing in OpenSearch Discover Dashboard

## Problem
- Documents exist in index (2638 total, 165 Azure)
- Documents are queryable via Dev Tools
- Documents don't appear in Discover dashboard UI

## Root Cause
**OpenSearch Discover requires a time field to be configured in the Index Pattern.**

Discover uses a time-based filter by default. If no time field is configured, or if the time field doesn't match your documents, Discover won't show any results.

## Solution: Configure Index Pattern

### Step 1: Create/Edit Index Pattern

1. Go to **Stack Management** → **Index Patterns**
2. Click **Create index pattern** (or edit existing)
3. Enter index pattern: `prowler-checks-benchmarks`
4. Click **Next step**

### Step 2: Configure Time Field

1. In the **Time field** dropdown, select: **`created_at`**
   - This is the field that contains timestamps in your documents
   - If `created_at` doesn't appear, click **Refresh field list** first

2. Click **Create index pattern**

### Step 3: Use Discover

1. Go to **Discover**
2. Select index pattern: **`prowler-checks-benchmarks`**
3. Set time range (top right):
   - Click time picker
   - Select **"Last 7 days"** or **"All time"**
   - Or set custom range to include your upload date

4. Documents should now appear!

## Alternative: Query Without Time Filter

If you can't configure the index pattern, use **Dev Tools** instead:

```json
GET prowler-checks-benchmarks/_search
{
  "query": {
    "match_all": {}
  },
  "size": 20
}
```

Or search for Azure documents:

```json
GET prowler-checks-benchmarks/_search
{
  "query": {
    "term": {
      "provider": "azure"
    }
  },
  "size": 20
}
```

## Verify Time Field

Your documents have this time field:
- **Field name:** `created_at`
- **Type:** `date`
- **Format:** ISO 8601 (e.g., `2026-01-20T22:42:29.486149`)

## Quick Test

After configuring the index pattern, test in Discover:

1. Go to Discover
2. Select `prowler-checks-benchmarks` index pattern
3. In search bar, type: `provider:azure`
4. Set time range to include today
5. Click refresh

You should see 165 Azure documents!

## Common Issues

**Issue:** "No time field found"
- **Solution:** Make sure `created_at` field exists and is of type `date` in the mapping

**Issue:** "No results found" even after configuring time field
- **Solution:**
  - Check time range includes your upload date (2026-01-20)
  - Try "All time" or "Last 30 days"
  - Remove any other filters

**Issue:** Index pattern shows 0 documents
- **Solution:**
  - Refresh the index pattern
  - Verify index name is exactly: `prowler-checks-benchmarks`
  - Check if you have read permissions

## Verification Commands

Check if time field is properly configured:

```json
GET prowler-checks-benchmarks/_mapping
```

Look for:
```json
"created_at": {
  "type": "date"
}
```

Check document timestamps:

```json
GET prowler-checks-benchmarks/_search
{
  "query": {"match_all": {}},
  "size": 1,
  "_source": ["check_id", "provider", "created_at"]
}
```
