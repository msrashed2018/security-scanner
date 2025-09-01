"""
Data models for the security scanner service.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
import json


class ScanTargetType(Enum):
    """Types of scan targets."""
    DOCKER_IMAGE = "docker_image"
    GIT_REPOSITORY = "git_repository"
    KUBERNETES_MANIFEST = "kubernetes_manifest"
    TERRAFORM_CODE = "terraform_code"
    FILESYSTEM = "filesystem"


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"
    
    @classmethod
    def from_string(cls, severity: str) -> 'SeverityLevel':
        """Convert string to SeverityLevel enum."""
        try:
            return cls(severity.upper())
        except ValueError:
            return cls.UNKNOWN


class ScanStatus(Enum):
    """Status of a scan operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


@dataclass
class ScanTarget:
    """Represents a target to be scanned."""
    path: str
    target_type: ScanTargetType
    name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.name is None:
            self.name = self.path.split('/')[-1] if '/' in self.path else self.path


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    scanner: str
    target: str
    location: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'scanner': self.scanner,
            'target': self.target,
            'location': self.location,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'references': self.references,
            'remediation': self.remediation,
            'metadata': self.metadata
        }


@dataclass
class ScanResult:
    """Represents the result of a single scanner execution."""
    scanner_name: str
    target: ScanTarget
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    raw_output: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def finding_counts(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        counts = {severity.value: 0 for severity in SeverityLevel}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            'scanner_name': self.scanner_name,
            'target': {
                'path': self.target.path,
                'type': self.target.target_type.value,
                'name': self.target.name,
                'metadata': self.target.metadata
            },
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'findings': [finding.to_dict() for finding in self.findings],
            'finding_counts': self.finding_counts,
            'raw_output': self.raw_output,
            'error_message': self.error_message,
            'metadata': self.metadata
        }


@dataclass
class ScanSummary:
    """Summary of all scan results."""
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    targets: List[ScanTarget] = field(default_factory=list)
    results: List[ScanResult] = field(default_factory=list)
    enabled_scanners: List[str] = field(default_factory=list)
    total_findings: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[float]:
        """Get total scan duration in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def overall_finding_counts(self) -> Dict[str, int]:
        """Get overall count of findings by severity across all scanners."""
        counts = {severity.value: 0 for severity in SeverityLevel}
        for result in self.results:
            for finding in result.findings:
                counts[finding.severity.value] += 1
        return counts
    
    @property
    def scanner_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary by scanner."""
        summary = {}
        for result in self.results:
            scanner = result.scanner_name
            if scanner not in summary:
                summary[scanner] = {
                    'total_scans': 0,
                    'successful_scans': 0,
                    'failed_scans': 0,
                    'total_findings': 0,
                    'finding_counts': {severity.value: 0 for severity in SeverityLevel}
                }
            
            summary[scanner]['total_scans'] += 1
            if result.status == ScanStatus.COMPLETED:
                summary[scanner]['successful_scans'] += 1
            elif result.status == ScanStatus.FAILED:
                summary[scanner]['failed_scans'] += 1
            
            summary[scanner]['total_findings'] += len(result.findings)
            for finding in result.findings:
                summary[scanner]['finding_counts'][finding.severity.value] += 1
        
        return summary
    
    @property
    def target_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary by target."""
        summary = {}
        for result in self.results:
            target_path = result.target.path
            if target_path not in summary:
                summary[target_path] = {
                    'target_type': result.target.target_type.value,
                    'scanners_run': [],
                    'total_findings': 0,
                    'finding_counts': {severity.value: 0 for severity in SeverityLevel}
                }
            
            summary[target_path]['scanners_run'].append(result.scanner_name)
            summary[target_path]['total_findings'] += len(result.findings)
            for finding in result.findings:
                summary[target_path]['finding_counts'][finding.severity.value] += 1
        
        return summary
    
    def get_high_severity_findings(self) -> List[Finding]:
        """Get all high and critical severity findings."""
        high_severity = []
        for result in self.results:
            for finding in result.findings:
                if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                    high_severity.append(finding)
        return high_severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan summary to dictionary."""
        return {
            'scan_id': self.scan_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'targets': [
                {
                    'path': target.path,
                    'type': target.target_type.value,
                    'name': target.name,
                    'metadata': target.metadata
                }
                for target in self.targets
            ],
            'enabled_scanners': self.enabled_scanners,
            'total_findings': self.total_findings,
            'overall_finding_counts': self.overall_finding_counts,
            'scanner_summary': self.scanner_summary,
            'target_summary': self.target_summary,
            'high_severity_findings': [f.to_dict() for f in self.get_high_severity_findings()],
            'results': [result.to_dict() for result in self.results],
            'metadata': self.metadata
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert scan summary to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)