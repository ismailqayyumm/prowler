# OpenSearch Work Directory

This directory contains scripts and tools for exploring and working with OpenSearch indices, specifically the `prowler-checks-benchmarks` index.

## Directory Structure

```
opensearch_work/
├── scripts/          # Python scripts for OpenSearch operations
├── data/             # Output data files (mappings, samples, etc.)
├── outputs/           # Log files and other outputs
└── README.md         # This file
```

## Setup

### Environment Variables

You need to set the following environment variables to connect to OpenSearch:

**Required:**
- `OPENSEARCH_HOST` - OpenSearch host address
- `OPENSEARCH_USERNAME` - OpenSearch username
- `OPENSEARCH_PASSWORD` - OpenSearch password

**Optional (with defaults):**
- `OPENSEARCH_PORT` - OpenSearch port (default: 9200)
- `OPENSEARCH_USE_SSL` - Use SSL connection (default: false)
- `OPENSEARCH_VERIFY_CERTS` - Verify SSL certificates (default: true)
- `OPENSEARCH_INDEX` - Index name to work with (default: prowler-checks-benchmarks)

### Setting Environment Variables

You can set them in several ways:

1. **Export in your shell:**
```bash
export OPENSEARCH_HOST="your-host.com"
export OPENSEARCH_PORT="443"
export OPENSEARCH_USERNAME="your-username"
export OPENSEARCH_PASSWORD="your-password"
export OPENSEARCH_USE_SSL="true"
```

2. **Create a .env file** (you can use the provided `load_env.sh` script):
```bash
# Create .env file in opensearch_work directory
cat > opensearch_work/.env << EOF
OPENSEARCH_HOST=your-host.com
OPENSEARCH_PORT=443
OPENSEARCH_USERNAME=your-username
OPENSEARCH_PASSWORD=your-password
OPENSEARCH_USE_SSL=true
OPENSEARCH_VERIFY_CERTS=true
OPENSEARCH_INDEX=prowler-checks-benchmarks
EOF

# Load and run
source opensearch_work/load_env.sh
```

3. **Load from .env file using the helper script:**
```bash
python3 opensearch_work/scripts/load_env_and_run.py opensearch_work/scripts/explore_index.py
```

## Scripts

### check_env.py

Check if OpenSearch environment variables are set:

```bash
python3 opensearch_work/scripts/check_env.py
```

### explore_index.py

Explore an OpenSearch index, extract its mapping, statistics, and sample documents:

```bash
python3 opensearch_work/scripts/explore_index.py --index prowler-checks-benchmarks --samples 10
```

**Options:**
- `--index`: Name of the index to explore (default: prowler-checks-benchmarks)
- `--samples`: Number of sample documents to retrieve (default: 10)
- `--output-dir`: Directory to save output files (default: opensearch_work/data)

**Outputs:**
- `exploration_results_*.json` - Full exploration results
- `index_mapping_*.json` - Index mapping/schema
- `sample_documents_*.json` - Sample documents from the index
- `index_summary_*.txt` - Human-readable summary

## Usage Example

1. **Check environment variables:**
```bash
python3 opensearch_work/scripts/check_env.py
```

2. **Explore the index:**
```bash
python3 opensearch_work/scripts/explore_index.py --index prowler-checks-benchmarks --samples 5
```

3. **View results:**
```bash
ls -lh opensearch_work/data/
cat opensearch_work/data/index_summary_*.txt
```

## Dependencies

The scripts require the `opensearch-py` Python package:

```bash
pip install opensearch-py
```

Or if using poetry:

```bash
poetry add opensearch-py
```

