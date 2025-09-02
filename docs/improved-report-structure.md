# Improved Report Directory Structure

## Implementation Status: ✅ COMPLETED

This document describes the new hierarchical report structure that has been implemented in the security scanner. The previous flat directory structure has been replaced with a well-organized, hierarchical system.

## Previous Problems (Now Resolved)
- ✅ Flat directory structure with all files mixed together
- ✅ Non-descriptive scan directory names  
- ✅ Individual scanner results mixed with summary reports
- ✅ No organization by target or scanner type

## Implemented Structure

```
reports/
├── index.html                                    # Auto-generated main index
├── container-scan-2025-09-01_20-04-46/         # Human readable scan_id with description
│   ├── index.html                               # Auto-generated scan index
│   ├── summary/                                 # Executive and detailed reports
│   │   ├── executive_summary.html
│   │   └── detailed_report.html
│   ├── targets/                                 # Organized by target
│   │   ├── nginx/                              # Target name
│   │   │   ├── index.html                      # Target summary
│   │   │   ├── combined_findings.json          # All findings for this target
│   │   │   └── scanners/                       # Individual scanner results
│   │   │       ├── trivy.json
│   │   │       ├── grype.json
│   │   │       ├── syft.json
│   │   │       └── dockle.json
│   │   └── ubuntu/                             # Another target
│   │       ├── index.html
│   │       ├── combined_findings.json
│   │       └── scanners/
│   │           ├── trivy.json
│   │           ├── grype.json
│   │           └── syft.json
│   ├── raw-data/                               # JSON and SARIF outputs
│   │   ├── container-scan-2025-09-01_20-04-46_summary.json
│   │   ├── container-scan-2025-09-01_20-04-46_findings.json
│   │   └── container-scan-2025-09-01_20-04-46.sarif
│   └── metadata/                               # Scan metadata
│       └── scan_metadata.json
├── container-scan-2025-09-01_19-55-37/         # Another scan session
│   ├── index.html
│   ├── summary/
│   ├── targets/
│   ├── raw-data/
│   └── metadata/
└── container-scan-2025-08-30_14-22-15/         # Older scan session
    ├── index.html
    ├── summary/
    ├── targets/
    ├── raw-data/
    └── metadata/
```

## Benefits

1. **Clear Hierarchy**: Summary → Targets → Scanners → Results
2. **Better Navigation**: Auto-generated index pages at each level
3. **Target Organization**: Easy to find results for specific targets
4. **Scanner Separation**: Individual scanner results are isolated
5. **Metadata Tracking**: Each scan has metadata for better organization
6. **Scalable**: Works for any number of targets and scanners
7. **Web-Friendly**: Multiple index pages for easy browsing
8. **Multiple Scans**: Each scan session gets its own timestamped directory
9. **Human Readable**: Timestamp format is easy to understand

## Naming Convention

- **Scan Directory**: `{description}-YYYY-MM-DD_HH-MM-SS`
  - Example: `container-scan-2025-09-01_20-04-46`
  - Includes scan description from YAML configuration
  - Human readable and sortable chronologically
  - Works for any scan type (container, git, k8s, terraform, filesystem)

- **Target Directory**: Use sanitized target name
  - Docker images: `nginx`, `ubuntu2004`
  - Git repos: `my-app`, `security-scanner`
  - Files: `deployment-yaml`, `main-tf`

- **File Organization**:
  - **Summary files**: `summary/` directory for HTML reports
  - **Target-specific**: `targets/{target}/` with combined findings and scanner subdirectories
  - **Raw data**: `raw-data/` for JSON and SARIF files
  - **Metadata**: `metadata/` for scan information

## Index Generation

Each directory level will have an auto-generated `index.html`:

1. **Main Index** (`reports/index.html`): Lists all scans chronologically
2. **Scan Index** (`{scan-id}/index.html`): Overview of specific scan results
3. **Target Index** (`targets/{target}/index.html`): Target-specific results