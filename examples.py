"""
Example usage of LLM-powered CVE detection system
Demonstrates various features and use cases
"""

import os
from cve_detector import CVEDetector, get_recommended_client
from llm_client import LLMClient, LLMProvider

# Example 1: Simple file scan
print("=" * 60)
print("Example 1: Scanning a single file")
print("=" * 60)

# Create a sample vulnerable file
sample_code = """
import sqlite3

def get_user_by_name(username):
    # VULNERABLE: SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(search_term):
    # VULNERABLE: Potential command injection
    import os
    os.system("grep " + search_term + " products.txt")

def render_page(user_input):
    # VULNERABLE: XSS
    return "<h1>Welcome " + user_input + "</h1>"
"""

# Save sample file
with open("vulnerable_example.py", "w") as f:
    f.write(sample_code)

try:
    # Initialize detector
    detector = CVEDetector()
    print(f"✓ Using {detector.primary_client.provider.value} - {detector.primary_client.model}\n")
    
    # Scan the file
    result = detector.scan_file("vulnerable_example.py")
    
    print(f"Scan Results:")
    print(f"  Summary: {result.summary}")
    print(f"  Vulnerabilities found: {len(result.findings)}\n")
    
    # Display findings
    for i, finding in enumerate(result.findings, 1):
        print(f"{i}. [{finding.severity.upper()}] {finding.vulnerability_type}")
        print(f"   Location: {finding.location}")
        print(f"   Description: {finding.description}")
        print(f"   Recommendation: {finding.recommendation}")
        if finding.cwe_id:
            print(f"   CWE: {finding.cwe_id}")
        print(f"   Confidence: {finding.confidence}\n")

except Exception as e:
    print(f"Error: {str(e)}")
    print("\nMake sure to set your API key:")
    print("  export ANTHROPIC_API_KEY='your-key'  # Recommended")
    print("  or")
    print("  export OPENAI_API_KEY='your-key'")

# Example 2: Scanning a directory
print("\n" + "=" * 60)
print("Example 2: Scanning CVE_Scrapy directory")
print("=" * 60)

try:
    detector = CVEDetector()
    
    # Scan the CVE_Scrapy directory
    report = detector.scan_directory(
        "CVE_Scrapy",
        extensions=['.py'],
        max_files=10
    )
    
    print(f"\n{report.summary}\n")
    print(f"Severity breakdown:")
    print(f"  Critical: {report.critical_count}")
    print(f"  High: {report.high_count}")
    print(f"  Medium: {report.medium_count}")
    print(f"  Low: {report.low_count}")
    
    # Export reports
    if report.vulnerabilities_found > 0:
        detector.export_report(report, "example_report.json", format='json')
        detector.export_report(report, "example_report.html", format='html')
        print(f"\n✓ Reports exported: example_report.json, example_report.html")
    
except Exception as e:
    print(f"Error: {str(e)}")

# Example 3: Specific provider selection
print("\n" + "=" * 60)
print("Example 3: Using specific LLM provider")
print("=" * 60)

# Use Anthropic Claude (if API key available)
if os.getenv("ANTHROPIC_API_KEY"):
    print("Using Anthropic Claude Sonnet...")
    client = LLMClient(provider=LLMProvider.ANTHROPIC)
    detector = CVEDetector(llm_client=client)
    print(f"✓ Configured with {client.model}")

# Use OpenAI GPT (if API key available)
elif os.getenv("OPENAI_API_KEY"):
    print("Using OpenAI GPT...")
    client = LLMClient(provider=LLMProvider.OPENAI)
    detector = CVEDetector(llm_client=client)
    print(f"✓ Configured with {client.model}")

else:
    print("No API keys found. Please set ANTHROPIC_API_KEY or OPENAI_API_KEY")

# Example 4: Batch processing
print("\n" + "=" * 60)
print("Example 4: Batch processing for better context")
print("=" * 60)

try:
    detector = CVEDetector()
    
    # Analyze files in batches to provide more context to the LLM
    print("Analyzing CVE_Scrapy in batches...")
    report = detector.scan_codebase_batch(
        "CVE_Scrapy",
        batch_size=3,  # Analyze 3 files together
        extensions=['.py']
    )
    
    print(f"\n{report.summary}")
    
except Exception as e:
    print(f"Error: {str(e)}")

# Example 5: Multi-model consensus (requires both API keys)
print("\n" + "=" * 60)
print("Example 5: Multi-model consensus (production mode)")
print("=" * 60)

if os.getenv("ANTHROPIC_API_KEY") and os.getenv("OPENAI_API_KEY"):
    print("Both API keys available - enabling multi-model consensus")
    try:
        detector = CVEDetector(enable_multi_model=True)
        result = detector.scan_file("vulnerable_example.py")
        
        print(f"\nMulti-model consensus results:")
        print(f"  High-confidence findings: {len([f for f in result.findings if f.confidence == 'high'])}")
        print(f"  Total findings: {len(result.findings)}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
else:
    print("Multi-model requires both ANTHROPIC_API_KEY and OPENAI_API_KEY")
    print("Set both environment variables to enable this feature")

print("\n" + "=" * 60)
print("Examples complete!")
print("=" * 60)

# Cleanup
if os.path.exists("vulnerable_example.py"):
    os.remove("vulnerable_example.py")
    print("\n✓ Cleaned up temporary files")
