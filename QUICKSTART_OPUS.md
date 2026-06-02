# Quick Start: Using Claude Opus 4.6 for CVE Detection

## Why Claude Opus 4.6?

Claude Opus 4.6 is the **most powerful** AI model available for security vulnerability detection, offering best-in-class accuracy for critical applications.

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set API Key
```bash
export ANTHROPIC_API_KEY='your-anthropic-api-key-here'
```

Get your API key from: https://console.anthropic.com/

### 3. Verify Setup
```bash
python3 -c "from cve_detector_opus import create_opus_detector; print('✓ Ready to scan!')"
```

## Basic Usage

### Scan a Single File
```bash
python cve_detector_opus.py myapp.py
```

### Scan a Directory
```bash
python cve_detector_opus.py ./myproject
```

### Scan Current Directory
```bash
python cve_detector_opus.py .
```

## Python API

```python
from cve_detector_opus import create_opus_detector

# Initialize with Claude Opus 4.6
detector = create_opus_detector()

# Scan a file
result = detector.scan_file("payment_processor.py")

# View findings
for finding in result.findings:
    print(f"[{finding.severity.upper()}] {finding.vulnerability_type}")
    print(f"Location: {finding.location}")
    print(f"Description: {finding.description}")
    print(f"Fix: {finding.recommendation}\n")

# Scan a directory
report = detector.scan_directory("./critical-app")

# Export reports
detector.export_report(report, "security_audit.json", format="json")
detector.export_report(report, "security_audit.html", format="html")

print(f"Found {report.vulnerabilities_found} vulnerabilities")
print(f"Critical: {report.critical_count}, High: {report.high_count}")
```

## Model Comparison

View detailed comparison of all available models:
```bash
python model_config.py
```

**Quick Reference:**

| Model | When to Use | Speed | Cost | Accuracy |
|-------|-------------|-------|------|----------|
| **Opus 4.6** | Critical apps, security audits | 🐢 Slow | 💰💰💰 High | ⭐⭐⭐⭐⭐ Best |
| **Sonnet 4.6** | CI/CD, regular scans | 🏃 Medium | 💰💰 Medium | ⭐⭐⭐⭐ Better |
| **Sonnet 3.7** | Development, fast feedback | ⚡ Fast | 💰 Low | ⭐⭐⭐ Good |

## When to Use Opus 4.6

✅ **USE OPUS 4.6 FOR:**
- Financial systems and banking applications
- Healthcare applications (PHI/PII handling)
- E-commerce payment processing
- Critical infrastructure
- Pre-release security audits
- Compliance-required security reviews
- High-value targets

⚠️ **USE SONNET 4.6 FOR:**
- CI/CD integration
- Regular security scanning
- General web applications
- Most production use cases

💡 **USE SONNET 3.7 FOR:**
- Development and testing
- Fast feedback loops
- Initial triage of large codebases
- Budget-conscious deployments

## Advanced Usage

### Choose Specific Model
```python
from llm_client import LLMClient, LLMProvider
from model_config import AnthropicModel
from cve_detector import CVEDetector

# Explicitly use Opus 4.6
client = LLMClient(
    provider=LLMProvider.ANTHROPIC,
    model=AnthropicModel.OPUS_4_6.value
)
detector = CVEDetector(llm_client=client)

# Or use Sonnet 4.6
client = LLMClient(
    provider=LLMProvider.ANTHROPIC,
    model=AnthropicModel.SONNET_4_6.value
)
detector = CVEDetector(llm_client=client)
```

### Tiered Scanning Strategy
```python
from llm_client import LLMClient, LLMProvider
from model_config import AnthropicModel
from cve_detector import CVEDetector

# Fast triage with Sonnet 3.7
detector_fast = CVEDetector(
    llm_client=LLMClient(
        provider=LLMProvider.ANTHROPIC,
        model=AnthropicModel.SONNET_3_7.value
    )
)

# Deep analysis with Opus 4.6
detector_deep = CVEDetector(
    llm_client=LLMClient(
        provider=LLMProvider.ANTHROPIC,
        model=AnthropicModel.OPUS_4_6.value
    )
)

# Step 1: Quick scan
print("Running fast initial scan...")
initial = detector_fast.scan_directory("./app")

# Step 2: Deep dive on critical findings
if initial.critical_count > 0:
    print("Running deep analysis with Opus 4.6...")
    detailed = detector_deep.scan_directory("./app/critical")
    print(f"Opus found {len(detailed.findings)} issues")
```

### Multi-Model Consensus
```python
from cve_detector_opus import create_opus_detector

# Requires both ANTHROPIC_API_KEY and OPENAI_API_KEY
detector = create_opus_detector(enable_multi_model=True)

# Only reports findings confirmed by multiple models
report = detector.scan_directory("./critical-app")
print(f"High-confidence findings: {report.vulnerabilities_found}")
```

## Examples

See complete examples:
```bash
# View all usage examples
python examples.py

# See model comparison
python model_config.py

# Run demo (no API key needed)
python demo.py
```

## Documentation

- **[OPUS_GUIDE.md](OPUS_GUIDE.md)** - Comprehensive guide to using Opus 4.6
- **[README.md](README.md)** - Full documentation
- **[LLM_RESEARCH.md](LLM_RESEARCH.md)** - Research and benchmarks
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Technical details

## Cost Estimation

Typical costs for Claude Opus 4.6:
- **Small file** (~100 lines): $0.01-0.02 per scan
- **Medium file** (~500 lines): $0.05-0.10 per scan
- **Large file** (~1000 lines): $0.10-0.20 per scan
- **Entire app** (~50 files): $2-10 total

**Cost vs Risk**: One prevented security breach ($4.5M average) makes Opus ROI > 100,000x

## Troubleshooting

### "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY='your-key-here'
```

### "Rate limit exceeded"
- Opus has lower rate limits than Sonnet
- Add delays between requests
- Consider using Sonnet for high-volume scanning

### "Model not available"
- Verify your API key has access to Claude Opus 4.6
- Check Anthropic console for API tier
- Alternative: Use Sonnet 4.6 (still excellent)

## Support

For detailed guidance, see:
- [OPUS_GUIDE.md](OPUS_GUIDE.md) - Complete usage guide
- [model_config.py](model_config.py) - Model comparison tool
- [examples.py](examples.py) - Working examples

---

**Ready to scan?** Run: `python cve_detector_opus.py .`
