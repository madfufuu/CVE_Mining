# CVE Mining Project

## Overview
A comprehensive CVE (Common Vulnerabilities and Exposures) detection and mining system that combines traditional web scraping with cutting-edge LLM-powered vulnerability detection.

### Project Components

#### 1. Traditional CVE Mining (Legacy)
- **CVE_spider.py** - Web scraper for MITRE CVE database
- **CVE_record_generator.py** - Generates structured CVE records

#### 2. LLM-Powered Vulnerability Detection (NEW)
- **llm_client.py** - Multi-provider LLM client (Anthropic, OpenAI)
- **cve_detector.py** - Automated vulnerability detection algorithm
- **test_cve_detection.py** - Comprehensive test suite

### Project Dependencies
```bash
pip install -r requirements.txt
```

**Core Dependencies:**
* Scrapy 2.4.1
* Python 3.8.8+
* Pandas 1.2.3
* Anthropic SDK (for Claude models)
* OpenAI SDK (for GPT models)
* pytest (for testing)

### Description
A hybrid system that combines manual CVE mining from MITRE's database with automated LLM-powered vulnerability detection. The new LLM detection system uses state-of-the-art AI models to identify security vulnerabilities in source code, significantly outperforming traditional rule-based scanners.
### Usage
<b>CVE_spider.py</b>
The spider needs to be dropped in an initialized Scrapy's "spiders" folder, follow the directions linked below to create a local Scrapy project.
<a href="https://docs.scrapy.org/en/latest/intro/tutorial.html#creating-a-project">Scrapy Documentation</a>

The spider then can be run from the project's top level directory with the following command

    scrapy crawl CVE_gold_miner

The above command will then generate a output file containing the crawled data in a csv file format.

Input:

&nbsp;&nbsp;&nbsp;&nbsp;Column of CVE_IDs to crawl in csv format named (CVE-ID)

Output:

&nbsp;&nbsp;&nbsp;&nbsp;CVE_Miner_output_batch\<mm-dd-yyyy\>.csv

Output Columns:

&nbsp;&nbsp;&nbsp;&nbsp;CVE_ID: ID of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;CVE_Link: Link to CVE record in MITRE\
&nbsp;&nbsp;&nbsp;&nbsp;Description: MITRE description of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;Reference_Link: Bug fix, commit, and reference links for CVE (Multiple cols)

<b>CVE_record_generator.py</b>\
Input: 

&nbsp;&nbsp;&nbsp;&nbsp;Batch file generated with CVE_spider.py with list of CVEs with detailed and structured data

Input:

&nbsp;&nbsp;&nbsp;&nbsp;CVE_ID: ID of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;CVE_Link: Link to CVE record in MITRE\
&nbsp;&nbsp;&nbsp;&nbsp;Description: MITRE description of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;Reference_Link: Bug fix, commit, and reference links for CVE\ (Multiple cols)

Output:

&nbsp;&nbsp;&nbsp;&nbsp;Create directories, explanation.txt, and fix.diff for each CVE record

---

## LLM-Powered CVE Detection (NEW)

### Background

Based on 2026 research, LLM models have proven to be **~3x more effective** than traditional rule-based static analysis tools at detecting vulnerabilities. Our implementation supports multiple leading models:

- **Claude Sonnet 4.6** (Recommended) - F3 score: 51.7 on RealVuln benchmark
- **GPT-4o / GPT-5.5** - Strong performance, widely available
- **Multi-model consensus** - For production environments requiring high confidence

### Setup

#### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 2. Configure API Keys

Set up your API key as an environment variable:

**For Anthropic Claude (Recommended):**
```bash
export ANTHROPIC_API_KEY='your-api-key-here'
```

**For OpenAI GPT:**
```bash
export OPENAI_API_KEY='your-api-key-here'
```

**Optional: Using .env file**
```bash
# Create .env file
echo "ANTHROPIC_API_KEY=your-key" > .env
pip install python-dotenv
```

#### 3. Verify Setup
```bash
python -c "from cve_detector import CVEDetector; print('✓ Setup successful')"
```

### Usage

#### Quick Start - Scan a Single File
```python
from cve_detector import CVEDetector

# Initialize detector (automatically uses best available model)
detector = CVEDetector()

# Scan a single file
result = detector.scan_file("path/to/your/code.py")

# Print findings
print(f"Found {len(result.findings)} vulnerabilities")
for finding in result.findings:
    print(f"[{finding.severity}] {finding.vulnerability_type}")
    print(f"  Location: {finding.location}")
    print(f"  Fix: {finding.recommendation}\n")
```

#### Scan Entire Directory
```python
from cve_detector import CVEDetector

detector = CVEDetector()

# Scan directory with default settings
report = detector.scan_directory("./myproject")

# Export reports
detector.export_report(report, "cve_report.json", format="json")
detector.export_report(report, "cve_report.html", format="html")

print(f"Analysis complete: {report.summary}")
```

#### Command Line Usage
```bash
# Scan current directory
python cve_detector.py .

# Scan specific directory
python cve_detector.py /path/to/project

# Scan single file
python cve_detector.py myapp.py
```

#### Advanced: Multi-Model Consensus
```python
from cve_detector import CVEDetector

# Enable multi-model validation for production use
# Requires both ANTHROPIC_API_KEY and OPENAI_API_KEY
detector = CVEDetector(enable_multi_model=True)

# Only includes findings confirmed by multiple models
report = detector.scan_directory("./critical-app")
```

#### Batch Processing
```python
from cve_detector import CVEDetector

detector = CVEDetector()

# Analyze files in batches for better context understanding
report = detector.scan_codebase_batch(
    "./project",
    batch_size=5,  # Analyze 5 files together
    extensions=['.py', '.js']  # Only Python and JavaScript
)
```

### Understanding the Output

#### Report Structure
```json
{
  "timestamp": "2026-06-02T12:00:00",
  "repository_path": "./myproject",
  "files_analyzed": 42,
  "vulnerabilities_found": 8,
  "critical_count": 2,
  "high_count": 3,
  "medium_count": 2,
  "low_count": 1,
  "summary": "Analysis summary...",
  "models_used": ["anthropic/claude-sonnet-4-20250514"],
  "findings": [...]
}
```

#### Vulnerability Finding
Each finding includes:
- **Severity**: critical, high, medium, low
- **Vulnerability Type**: SQL Injection, XSS, etc.
- **Description**: Detailed explanation
- **Location**: File path and line numbers
- **Affected Code**: The vulnerable code snippet
- **Recommendation**: How to fix the vulnerability
- **CWE ID**: Common Weakness Enumeration identifier
- **Confidence**: high, medium, low

### Supported Languages

The system supports vulnerability detection in:
- Python (.py)
- JavaScript/TypeScript (.js, .ts)
- Java (.java)
- PHP (.php)
- C/C++ (.c, .cpp)
- Go (.go)
- Ruby (.rb)
- Rust (.rs)

### Best Practices

1. **API Keys**: Store API keys securely using environment variables or secret management systems
2. **Rate Limits**: Be aware of API rate limits when scanning large codebases
3. **Human Review**: Always review LLM findings - they are assistive tools, not replacements for security experts
4. **Multi-Model**: Use multi-model consensus for critical production applications
5. **Regular Scans**: Integrate into CI/CD pipeline for continuous security monitoring

### Testing

Run the test suite:
```bash
# Unit tests (no API key required)
pytest test_cve_detection.py -v

# Integration tests (requires API key)
ANTHROPIC_API_KEY=your-key pytest test_cve_detection.py -v
```

### Research & Model Selection

See [LLM_RESEARCH.md](LLM_RESEARCH.md) for detailed research on LLM model selection and performance benchmarks.

**Key Findings:**
- LLM scanners score ~3x higher than traditional tools (F3: 51.7 vs 17.7)
- Claude Sonnet 4.6 recommended for best balance of performance and availability
- Context-aware analysis detects logic flaws missed by pattern-matching tools

### Troubleshooting

**"No API keys found" error:**
- Ensure you've set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable
- Check the key is correctly exported in your shell session

**"Failed to parse LLM response" error:**
- The LLM response format may have changed
- Try with a different model or contact support

**Rate limiting errors:**
- Reduce batch_size or max_files parameters
- Add delays between API calls
- Upgrade to higher API tier if available

### Security Considerations

⚠️ **Important**: When scanning code:
- Do not send proprietary/sensitive code to public LLM APIs without proper authorization
- Consider using on-premises LLM deployments for highly sensitive codebases
- Review your organization's policies on using AI services with code

### Contributing

To extend the system:
1. Add new LLM providers in `llm_client.py`
2. Implement provider-specific clients following the existing pattern
3. Add tests in `test_cve_detection.py`
4. Update documentation

---

## Legacy CVE Mining Tools