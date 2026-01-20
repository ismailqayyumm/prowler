# Secure Work Directory

This directory contains security-related work including OpenSearch integration and LLM risk labeling for Prowler security checks.

## Structure

- **opensearch_work/**: OpenSearch integration scripts and documentation
  - Scripts for exploring, extracting, and uploading Azure security checks
  - Documentation on index mapping and field structure
  
- **LLM_risk_labelling/**: LLM-based risk labeling system
  - Azure check risk labeling using MITRE ATT&CK framework
  - Integration with AWS Bedrock (Claude) for automated risk classification

## Environment Variables

All scripts require environment variables to be set. See individual README files in each subdirectory for specific requirements.

**Important**: Never commit `.env` files or credentials to the repository.

