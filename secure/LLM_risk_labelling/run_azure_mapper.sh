#!/bin/bash
# Script to run Azure mapper with proper environment setup

echo "Azure Risk Labeling - MITRE ATT&CK Mapping"
echo "=========================================="
echo ""
echo "Make sure you:"
echo "1. Have activated your virtual environment (venv)"
echo "2. Have installed: pip install pandas boto3"
echo "3. Have AWS credentials set in environment variables"
echo ""
echo "Running azure_mapper.py..."
echo ""

# Check if pandas is available
python3 -c "import pandas" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Error: pandas is not installed"
    echo "Please install it: pip install pandas boto3"
    exit 1
fi

# Check if boto3 is available
python3 -c "import boto3" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Error: boto3 is not installed"
    echo "Please install it: pip install pandas boto3"
    exit 1
fi

# Run the mapper
python3 azure_mapper.py
