"""
CVE Detection Algorithm powered by LLMs
Automatically detects potential vulnerabilities in codebases
"""

import os
import ast
import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime

from llm_client import (
    LLMClient,
    LLMProvider,
    VulnerabilityFinding,
    AnalysisResult,
    get_recommended_client
)


@dataclass
class CVEDetectionReport:
    """Complete CVE detection report"""
    timestamp: str
    repository_path: str
    files_analyzed: int
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[Dict]
    summary: str
    models_used: List[str]


class CVEDetector:
    """
    Automated CVE detection using LLM analysis
    """
    
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        enable_multi_model: bool = False
    ):
        """
        Initialize CVE detector
        
        Args:
            llm_client: LLM client to use (if None, uses recommended client)
            enable_multi_model: If True, uses multiple models for consensus
        """
        self.primary_client = llm_client or get_recommended_client()
        self.enable_multi_model = enable_multi_model
        self.secondary_client = None
        
        if enable_multi_model:
            self._setup_secondary_client()
    
    def _setup_secondary_client(self):
        """Setup secondary client for multi-model consensus"""
        # If primary is Anthropic, use OpenAI as secondary (or vice versa)
        if self.primary_client.provider == LLMProvider.ANTHROPIC:
            if os.getenv("OPENAI_API_KEY"):
                self.secondary_client = LLMClient(provider=LLMProvider.OPENAI)
        elif self.primary_client.provider == LLMProvider.OPENAI:
            if os.getenv("ANTHROPIC_API_KEY"):
                self.secondary_client = LLMClient(provider=LLMProvider.ANTHROPIC)
    
    def scan_file(
        self,
        file_path: str,
        language: Optional[str] = None
    ) -> AnalysisResult:
        """
        Scan a single file for vulnerabilities
        
        Args:
            file_path: Path to file to analyze
            language: Programming language (auto-detected if None)
            
        Returns:
            AnalysisResult with vulnerability findings
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        if not language:
            language = self._detect_language(file_path)
        
        result = self.primary_client.analyze_code(
            code=code,
            file_path=file_path,
            language=language
        )
        
        # Multi-model consensus if enabled
        if self.enable_multi_model and self.secondary_client:
            secondary_result = self.secondary_client.analyze_code(
                code=code,
                file_path=file_path,
                language=language
            )
            result = self._merge_results(result, secondary_result)
        
        return result
    
    def scan_directory(
        self,
        directory_path: str,
        extensions: Optional[List[str]] = None,
        exclude_dirs: Optional[Set[str]] = None,
        max_files: int = 100
    ) -> CVEDetectionReport:
        """
        Scan a directory for vulnerabilities
        
        Args:
            directory_path: Path to directory to scan
            extensions: List of file extensions to scan (e.g., ['.py', '.js'])
            exclude_dirs: Set of directory names to exclude
            max_files: Maximum number of files to analyze
            
        Returns:
            CVEDetectionReport with all findings
        """
        if not os.path.isdir(directory_path):
            raise NotADirectoryError(f"Not a directory: {directory_path}")
        
        # Default extensions for common languages
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.php', '.c', '.cpp', '.go', '.rb', '.rs']
        
        # Default excluded directories
        if exclude_dirs is None:
            exclude_dirs = {
                '__pycache__', 'node_modules', '.git', '.venv', 'venv',
                'env', 'dist', 'build', '.pytest_cache', '.mypy_cache'
            }
        
        # Collect files to analyze
        files_to_analyze = []
        for root, dirs, files in os.walk(directory_path):
            # Remove excluded directories from traversal
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    files_to_analyze.append(file_path)
                    
                    if len(files_to_analyze) >= max_files:
                        break
            
            if len(files_to_analyze) >= max_files:
                break
        
        print(f"Found {len(files_to_analyze)} files to analyze")
        
        # Analyze files
        all_findings = []
        models_used = set()
        
        for i, file_path in enumerate(files_to_analyze, 1):
            print(f"Analyzing {i}/{len(files_to_analyze)}: {file_path}")
            try:
                result = self.scan_file(file_path)
                all_findings.extend(result.findings)
                models_used.add(f"{result.provider}/{result.model_used}")
            except Exception as e:
                print(f"Error analyzing {file_path}: {str(e)}")
                continue
        
        # Generate report
        return self._generate_report(
            directory_path,
            len(files_to_analyze),
            all_findings,
            list(models_used)
        )
    
    def scan_codebase_batch(
        self,
        directory_path: str,
        batch_size: int = 5,
        extensions: Optional[List[str]] = None
    ) -> CVEDetectionReport:
        """
        Scan codebase in batches for better performance with multi-file context
        
        Args:
            directory_path: Path to directory to scan
            batch_size: Number of files to analyze together
            extensions: File extensions to include
            
        Returns:
            CVEDetectionReport with all findings
        """
        if not os.path.isdir(directory_path):
            raise NotADirectoryError(f"Not a directory: {directory_path}")
        
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.php']
        
        exclude_dirs = {
            '__pycache__', 'node_modules', '.git', '.venv', 'venv'
        }
        
        # Collect files
        files_to_analyze = []
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    files_to_analyze.append(file_path)
        
        print(f"Found {len(files_to_analyze)} files to analyze in batches of {batch_size}")
        
        all_findings = []
        models_used = set()
        
        # Process in batches
        for i in range(0, len(files_to_analyze), batch_size):
            batch = files_to_analyze[i:i + batch_size]
            print(f"\nAnalyzing batch {i//batch_size + 1}/{(len(files_to_analyze)-1)//batch_size + 1}")
            
            # Read batch files
            batch_files = {}
            language = None
            for file_path in batch:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        batch_files[file_path] = f.read()
                    if not language:
                        language = self._detect_language(file_path)
                except Exception as e:
                    print(f"Error reading {file_path}: {str(e)}")
                    continue
            
            if not batch_files:
                continue
            
            # Analyze batch
            try:
                result = self.primary_client.analyze_multiple_files(
                    batch_files,
                    language=language or "unknown"
                )
                all_findings.extend(result.findings)
                models_used.add(f"{result.provider}/{result.model_used}")
            except Exception as e:
                print(f"Error analyzing batch: {str(e)}")
                continue
        
        return self._generate_report(
            directory_path,
            len(files_to_analyze),
            all_findings,
            list(models_used)
        )
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp',
            '.go': 'go',
            '.rb': 'ruby',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.cs': 'csharp'
        }
        ext = os.path.splitext(file_path)[1].lower()
        return ext_map.get(ext, 'unknown')
    
    def _merge_results(
        self,
        primary: AnalysisResult,
        secondary: AnalysisResult
    ) -> AnalysisResult:
        """
        Merge results from multiple models (consensus approach)
        Only includes findings that appear in both results
        """
        # Simple consensus: only include high-confidence findings from primary
        # or findings that appear in both
        primary_vuln_types = {
            (f.vulnerability_type, f.location): f for f in primary.findings
        }
        secondary_vuln_types = {
            (f.vulnerability_type, f.location): f for f in secondary.findings
        }
        
        # Findings that appear in both
        consensus_findings = []
        for key in primary_vuln_types:
            if key in secondary_vuln_types:
                finding = primary_vuln_types[key]
                finding.confidence = "high"  # Both models agree
                consensus_findings.append(finding)
            elif primary_vuln_types[key].confidence == "high":
                consensus_findings.append(primary_vuln_types[key])
        
        return AnalysisResult(
            findings=consensus_findings,
            summary=f"Multi-model consensus analysis: {len(consensus_findings)} high-confidence findings",
            total_files_analyzed=primary.total_files_analyzed,
            model_used=f"{primary.model_used}+{secondary.model_used}",
            provider="multi-model"
        )
    
    def _generate_report(
        self,
        repo_path: str,
        files_count: int,
        findings: List[VulnerabilityFinding],
        models_used: List[str]
    ) -> CVEDetectionReport:
        """Generate comprehensive detection report"""
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for finding in findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Convert findings to dict
        findings_dict = [asdict(f) for f in findings]
        
        # Generate summary
        summary = f"Analyzed {files_count} files. Found {len(findings)} potential vulnerabilities: "
        summary += f"{severity_counts['critical']} critical, {severity_counts['high']} high, "
        summary += f"{severity_counts['medium']} medium, {severity_counts['low']} low."
        
        return CVEDetectionReport(
            timestamp=datetime.now().isoformat(),
            repository_path=repo_path,
            files_analyzed=files_count,
            vulnerabilities_found=len(findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            findings=findings_dict,
            summary=summary,
            models_used=models_used
        )
    
    def export_report(
        self,
        report: CVEDetectionReport,
        output_path: str,
        format: str = 'json'
    ):
        """
        Export report to file
        
        Args:
            report: CVEDetectionReport to export
            output_path: Path to output file
            format: Output format ('json' or 'html')
        """
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(asdict(report), f, indent=2)
            print(f"Report exported to {output_path}")
        
        elif format == 'html':
            html = self._generate_html_report(report)
            with open(output_path, 'w') as f:
                f.write(html)
            print(f"HTML report exported to {output_path}")
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_html_report(self, report: CVEDetectionReport) -> str:
        """Generate HTML report"""
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        findings_html = ""
        for i, finding in enumerate(report.findings, 1):
            severity = finding['severity'].lower()
            color = severity_colors.get(severity, '#6c757d')
            
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; margin-bottom: 20px; padding: 15px; background: #f8f9fa;">
                <h3>#{i} - {finding['vulnerability_type']} 
                    <span style="background: {color}; color: white; padding: 3px 10px; border-radius: 3px; font-size: 14px;">
                        {finding['severity'].upper()}
                    </span>
                </h3>
                <p><strong>Location:</strong> {finding['location']}</p>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>Affected Code:</strong></p>
                <pre style="background: #e9ecef; padding: 10px; overflow-x: auto;">{finding['affected_code']}</pre>
                <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
                {f"<p><strong>CWE ID:</strong> {finding['cwe_id']}</p>" if finding.get('cwe_id') else ""}
                <p><strong>Confidence:</strong> {finding['confidence']}</p>
            </div>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CVE Detection Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #ffffff; }}
                .header {{ background: #343a40; color: white; padding: 20px; margin-bottom: 30px; }}
                .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .stat-box {{ flex: 1; padding: 15px; background: #f8f9fa; border-radius: 5px; text-align: center; }}
                .stat-number {{ font-size: 32px; font-weight: bold; }}
                .stat-label {{ color: #6c757d; font-size: 14px; }}
                pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>CVE Detection Report</h1>
                <p>Generated: {report.timestamp}</p>
                <p>Repository: {report.repository_path}</p>
                <p>Models Used: {', '.join(report.models_used)}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{report.files_analyzed}</div>
                    <div class="stat-label">Files Analyzed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #dc3545;">{report.critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #fd7e14;">{report.high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #ffc107;">{report.medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #28a745;">{report.low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            
            <h2>Summary</h2>
            <p>{report.summary}</p>
            
            <h2>Findings</h2>
            {findings_html if findings_html else "<p>No vulnerabilities detected.</p>"}
        </body>
        </html>
        """
        
        return html


def main():
    """Example usage"""
    print("CVE Detection System - LLM Powered")
    print("=" * 50)
    
    # Initialize detector
    try:
        detector = CVEDetector()
        print(f"✓ Initialized with {detector.primary_client.provider.value} - {detector.primary_client.model}")
    except Exception as e:
        print(f"✗ Failed to initialize: {str(e)}")
        print("\nPlease set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable")
        return
    
    # Example: Scan current directory
    import sys
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        target_path = "."
    
    print(f"\nScanning: {target_path}")
    print("=" * 50)
    
    try:
        if os.path.isfile(target_path):
            result = detector.scan_file(target_path)
            print(f"\n{result.summary}")
            print(f"Found {len(result.findings)} potential vulnerabilities")
            
            for i, finding in enumerate(result.findings, 1):
                print(f"\n{i}. [{finding.severity.upper()}] {finding.vulnerability_type}")
                print(f"   Location: {finding.location}")
                print(f"   {finding.description[:100]}...")
        
        else:
            report = detector.scan_directory(target_path, max_files=50)
            print(f"\n{report.summary}")
            
            # Export report
            output_file = f"cve_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            detector.export_report(report, output_file, format='json')
            
            html_file = f"cve_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            detector.export_report(report, html_file, format='html')
            
            print(f"\n✓ Reports generated: {output_file}, {html_file}")
    
    except Exception as e:
        print(f"\n✗ Error during scan: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
