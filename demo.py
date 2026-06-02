"""
Demo script showing LLM-powered CVE detection system structure
This script demonstrates the system without requiring API keys
"""

from llm_client import LLMProvider, VulnerabilityFinding, AnalysisResult
from cve_detector import CVEDetectionReport
from datetime import datetime

print("=" * 70)
print("LLM-Powered CVE Detection System - Demo")
print("=" * 70)

# Show available providers
print("\n📋 Available LLM Providers:")
print(f"  • {LLMProvider.ANTHROPIC.value} (Recommended - Claude Sonnet 4.6)")
print(f"  • {LLMProvider.OPENAI.value} (GPT-4o)")

# Show system structure
print("\n🏗️  System Architecture:")
print("  1. llm_client.py - Multi-provider LLM client")
print("     - LLMClient: Main client class")
print("     - VulnerabilityFinding: Structured finding data")
print("     - AnalysisResult: Complete analysis results")
print("")
print("  2. cve_detector.py - Automated vulnerability detection")
print("     - CVEDetector: Main detector class")
print("     - scan_file(): Analyze single files")
print("     - scan_directory(): Analyze entire directories")
print("     - scan_codebase_batch(): Batch processing")
print("")
print("  3. test_cve_detection.py - Comprehensive test suite")
print("     - Unit tests for all components")
print("     - Integration tests with real APIs")

# Show example vulnerability finding structure
print("\n🔍 Vulnerability Finding Structure:")
example_finding = VulnerabilityFinding(
    severity="high",
    vulnerability_type="SQL Injection",
    description="User input concatenated directly into SQL query",
    location="app.py:lines 42-45",
    affected_code='query = "SELECT * FROM users WHERE id=" + user_id',
    recommendation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
    cwe_id="CWE-89",
    confidence="high"
)

print(f"  • Severity: {example_finding.severity}")
print(f"  • Type: {example_finding.vulnerability_type}")
print(f"  • CWE: {example_finding.cwe_id}")
print(f"  • Confidence: {example_finding.confidence}")
print(f"  • Location: {example_finding.location}")
print(f"  • Recommendation: {example_finding.recommendation[:50]}...")

# Show example report structure
print("\n📊 Detection Report Structure:")
example_report = CVEDetectionReport(
    timestamp=datetime.now().isoformat(),
    repository_path="./example-project",
    files_analyzed=42,
    vulnerabilities_found=8,
    critical_count=1,
    high_count=3,
    medium_count=3,
    low_count=1,
    findings=[],
    summary="Example report summary",
    models_used=["anthropic/claude-sonnet-4-20250514"]
)

print(f"  • Files analyzed: {example_report.files_analyzed}")
print(f"  • Total vulnerabilities: {example_report.vulnerabilities_found}")
print(f"  • Breakdown:")
print(f"    - Critical: {example_report.critical_count}")
print(f"    - High: {example_report.high_count}")
print(f"    - Medium: {example_report.medium_count}")
print(f"    - Low: {example_report.low_count}")

# Show supported languages
print("\n🌐 Supported Languages:")
languages = [
    "Python (.py)", "JavaScript (.js)", "TypeScript (.ts)",
    "Java (.java)", "PHP (.php)", "C/C++ (.c, .cpp)",
    "Go (.go)", "Ruby (.rb)", "Rust (.rs)"
]
for lang in languages:
    print(f"  • {lang}")

# Show key features
print("\n✨ Key Features:")
features = [
    "Multi-provider support (Anthropic & OpenAI)",
    "Single file and directory scanning",
    "Batch processing for better context",
    "Multi-model consensus for production",
    "JSON and HTML report generation",
    "Severity classification (Critical/High/Medium/Low)",
    "CWE mapping for vulnerabilities",
    "Confidence scoring",
    "~3x better than traditional rule-based tools"
]
for i, feature in enumerate(features, 1):
    print(f"  {i}. {feature}")

# Show research-backed performance
print("\n📈 Performance (Based on 2026 Research):")
print("  • RealVuln Benchmark F3 Scores:")
print("    - Claude Sonnet 4.6: 51.7")
print("    - Semgrep (rule-based): 17.7")
print("    - Improvement: ~3x better")
print("")
print("  • Detection Capabilities:")
print("    - SQL Injection ✓")
print("    - Cross-Site Scripting (XSS) ✓")
print("    - Command Injection ✓")
print("    - Authentication Issues ✓")
print("    - Logic Flaws ✓")
print("    - Access Control Problems ✓")

# Show setup requirements
print("\n⚙️  Setup Requirements:")
print("  1. Install dependencies:")
print("     pip install -r requirements.txt")
print("")
print("  2. Set API key (choose one):")
print("     export ANTHROPIC_API_KEY='your-key'  # Recommended")
print("     export OPENAI_API_KEY='your-key'")
print("")
print("  3. Run detection:")
print("     python cve_detector.py /path/to/code")

# Show example usage
print("\n💻 Quick Usage Example:")
print("""
from cve_detector import CVEDetector

# Initialize
detector = CVEDetector()

# Scan a file
result = detector.scan_file("app.py")

# View findings
for finding in result.findings:
    print(f"[{finding.severity}] {finding.vulnerability_type}")
    print(f"Location: {finding.location}")
    print(f"Fix: {finding.recommendation}")
""")

print("\n" + "=" * 70)
print("To get started, set your API key and run:")
print("  python cve_detector.py .")
print("  python examples.py")
print("=" * 70)
print("\n✓ Demo complete! System ready for use.")
