# Improved Report Directory Structure

## Current Problems
- Flat directory structure with all files mixed together
- Non-descriptive scan directory names
- Individual scanner results mixed with summary reports
- No organization by target or scanner type

## Proposed Structure

```
reports/
├── index.html                                    # Auto-generated main index
├── 2025-09-01_20-04-46/                        # Human readable timestamp as scan_id
│   ├── index.html                               # Auto-generated scan index
│   ├── metadata.json                            # Scan metadata and summary
│   ├── summary/                                 # High-level reports
│   │   ├── executive_summary.html
│   │   ├── detailed_report.html
│   │   ├── findings_summary.json
│   │   └── scan_summary.sarif
│   ├── targets/                                 # Organized by target
│   │   ├── nginx/                              # Target name
│   │   │   ├── index.html                      # Target summary
│   │   │   ├── scanners/                       # Individual scanner results
│   │   │   │   ├── trivy/
│   │   │   │   │   ├── report.html
│   │   │   │   │   ├── findings.json
│   │   │   │   │   └── raw_output.txt
│   │   │   │   ├── grype/
│   │   │   │   │   ├── report.html
│   │   │   │   │   ├── findings.json
│   │   │   │   │   └── raw_output.txt
│   │   │   │   └── dockle/
│   │   │   │       ├── report.html
│   │   │   │       ├── findings.json
│   │   │   │       └── raw_output.txt
│   │   │   └── combined_findings.json          # All findings for this target
│   │   └── ubuntu/                             # Another target
│   │       ├── index.html
│   │       ├── scanners/
│   │       │   ├── trivy/
│   │       │   ├── grype/
│   │       │   └── syft/
│   │       └── combined_findings.json
│   └── raw/                                    # Raw scanner outputs (optional)
│       ├── trivy_nginx.json
│       ├── grype_ubuntu.json
│       └── ...
├── 2025-09-01_19-55-37/                        # Another scan session
│   ├── index.html
│   ├── metadata.json
│   ├── summary/
│   ├── targets/
│   └── raw/
└── 2025-08-30_14-22-15/                        # Older scan session
    ├── index.html
    ├── metadata.json
    ├── summary/
    ├── targets/
    └── raw/
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

- **Scan Directory**: `YYYY-MM-DD_HH-MM-SS`
  - Example: `2025-09-01_20-04-46`
  - Human readable and sortable chronologically
  - Works for any scan type (container, git, k8s, terraform, filesystem)

- **Target Directory**: Use sanitized target name
  - Docker images: `nginx`, `ubuntu-22-04`
  - Git repos: `my-app`, `security-scanner`
  - Files: `deployment-yaml`, `main-tf`

## Index Generation

Each directory level will have an auto-generated `index.html`:

1. **Main Index** (`reports/index.html`): Lists all scans chronologically
2. **Scan Index** (`{scan-id}/index.html`): Overview of specific scan results
3. **Target Index** (`targets/{target}/index.html`): Target-specific results