"""
Report generation for bug bounty findings
Generates structured reports in multiple formats
"""

import json
import os
from datetime import datetime
from backend.utils.logger import BugBountyLogger

class Reporter:
    def __init__(self, output_dir="reports", logger=None):
        self.output_dir = output_dir
        self.logger = logger or BugBountyLogger()
        self.findings = []
        self.scan_info = {}
        
        os.makedirs(output_dir, exist_ok=True)
    
    def set_scan_info(self, target, scan_type, start_time):
        """Set scan metadata"""
        self.scan_info = {
            "target": target,
            "scan_type": scan_type,
            "start_time": start_time,
            "end_time": None,
            "duration": None
        }
    
    def add_finding(self, severity, title, description, evidence=None, remediation=None):
        """
        Add a security finding
        
        Args:
            severity: critical, high, medium, low, info
            title: Short title of the finding
            description: Detailed description
            evidence: Proof of concept or evidence
            remediation: Suggested fix
        """
        finding = {
            "id": len(self.findings) + 1,
            "severity": severity.lower(),
            "title": title,
            "description": description,
            "evidence": evidence or "N/A",
            "remediation": remediation or "N/A",
            "timestamp": datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        self.logger.finding(severity, title, description)
    
    def finalize_scan(self):
        """Finalize scan timing"""
        if self.scan_info.get("start_time"):
            self.scan_info["end_time"] = datetime.now().isoformat()
            start = datetime.fromisoformat(self.scan_info["start_time"])
            end = datetime.fromisoformat(self.scan_info["end_time"])
            duration = (end - start).total_seconds()
            self.scan_info["duration"] = f"{duration:.2f} seconds"
    
    def generate_json_report(self):
        """Generate JSON report"""
        self.finalize_scan()
        
        report = {
            "scan_info": self.scan_info,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"] == "critical"),
                "high": sum(1 for f in self.findings if f["severity"] == "high"),
                "medium": sum(1 for f in self.findings if f["severity"] == "medium"),
                "low": sum(1 for f in self.findings if f["severity"] == "low"),
                "info": sum(1 for f in self.findings if f["severity"] == "info")
            },
            "findings": self.findings
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.success(f"JSON report saved: {filepath}")
        return filepath
    
    def generate_markdown_report(self):
        """Generate Markdown report"""
        self.finalize_scan()
        
        md = "# Bug Bounty Security Report\n\n"
        
        # Scan info
        md += "## Scan Information\n\n"
        md += f"- **Target**: {self.scan_info.get('target', 'N/A')}\n"
        md += f"- **Scan Type**: {self.scan_info.get('scan_type', 'N/A')}\n"
        md += f"- **Start Time**: {self.scan_info.get('start_time', 'N/A')}\n"
        md += f"- **Duration**: {self.scan_info.get('duration', 'N/A')}\n\n"
        
        # Summary
        md += "## Summary\n\n"
        md += f"- **Total Findings**: {len(self.findings)}\n"
        md += f"- **Critical**: {sum(1 for f in self.findings if f['severity'] == 'critical')}\n"
        md += f"- **High**: {sum(1 for f in self.findings if f['severity'] == 'high')}\n"
        md += f"- **Medium**: {sum(1 for f in self.findings if f['severity'] == 'medium')}\n"
        md += f"- **Low**: {sum(1 for f in self.findings if f['severity'] == 'low')}\n"
        md += f"- **Info**: {sum(1 for f in self.findings if f['severity'] == 'info')}\n\n"
        
        # Findings
        md += "## Findings\n\n"
        
        for finding in sorted(self.findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x["severity"])):
            md += f"### {finding['id']}. {finding['title']}\n\n"
            md += f"**Severity**: {finding['severity'].upper()}\n\n"
            md += f"**Description**: {finding['description']}\n\n"
            md += f"**Evidence**:\n```\n{finding['evidence']}\n```\n\n"
            md += f"**Remediation**: {finding['remediation']}\n\n"
            md += "---\n\n"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(md)
        
        self.logger.success(f"Markdown report saved: {filepath}")
        return filepath
    
    def print_summary(self):
        """Print findings summary to console"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.scan_info.get('target', 'N/A')}")
        print(f"Duration: {self.scan_info.get('duration', 'N/A')}")
        print(f"\nTotal Findings: {len(self.findings)}")
        print(f"  Critical: {sum(1 for f in self.findings if f['severity'] == 'critical')}")
        print(f"  High: {sum(1 for f in self.findings if f['severity'] == 'high')}")
        print(f"  Medium: {sum(1 for f in self.findings if f['severity'] == 'medium')}")
        print(f"  Low: {sum(1 for f in self.findings if f['severity'] == 'low')}")
        print(f"  Info: {sum(1 for f in self.findings if f['severity'] == 'info')}")
        print("="*60 + "\n")
