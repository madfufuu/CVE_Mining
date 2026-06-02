# LLM Research for CVE Detection

## Executive Summary

As of June 2026, Large Language Models have become highly effective at detecting code vulnerabilities, significantly outperforming traditional rule-based static analysis tools.

## Top Models for Vulnerability Detection

### 1. **Claude Sonnet 4.6** (Anthropic) - RECOMMENDED
- **Availability**: Generally available via API
- **Performance**: F3 score of 51.7 on RealVuln benchmark
- **Strengths**: 
  - Context-aware analysis
  - High precision (~0.78) and recall (~0.49)
  - Excellent at detecting logic errors and access control issues
  - Reliable completion rate

### 2. **GPT-5.5** (OpenAI)
- **Availability**: Generally available
- **Performance**: XBOW benchmark shows Mythos-class performance
- **Strengths**:
  - Fast, cost-predictable analysis
  - Strong at structured vulnerability triage
  - Good for binary reverse engineering

### 3. **Claude Opus 4.6/4.7** (Anthropic) - PREMIUM CHOICE
- **Availability**: Generally available (4.6), Enterprise for 4.7
- **Performance**: Best-in-class for deep security analysis
- **Strengths**:
  - Most powerful reasoning capabilities
  - Excellent for complex vulnerability chains
  - Best for critical application audits
  - Superior at detecting subtle logic flaws
- **Considerations**: 
  - Higher cost per analysis
  - Slower than Sonnet (deeper analysis)
  - 27% repo failure rate under strict time constraints (compensated by accuracy)
  - Recommended for high-value targets and comprehensive audits

### 4. **Specialized Scanners**
- **Kolega.Dev**: F3 score of 73.0 (best specialized tool)
- Note: More accurate but require specific setup

## Key Research Findings

1. **Performance Comparison**:
   - Security-Specialized scanners: F3 ~73.0
   - General-Purpose LLMs: F3 ~51.7 (Claude Sonnet 4.6)
   - Rule-Based SAST: F3 ~17.7 (Semgrep)
   - **LLMs score ~3x higher than traditional tools**

2. **Multi-Model Consensus**:
   - Production systems use multiple models for validation
   - Reduces false positive rates
   - Requires independent findings from 2+ models

3. **Capabilities**:
   - Contextual reasoning (not just pattern matching)
   - Detection of complex logic flaws
   - Broken access control identification
   - Autonomous exploit chain construction

## Recommendation for Implementation

### For Critical/High-Value Applications

**Primary**: Use **Claude Opus 4.6** via Anthropic API
- **BEST** accuracy and depth of analysis
- Superior at detecting complex vulnerability chains
- Excellent for comprehensive security audits
- Recommended for: Financial systems, healthcare, critical infrastructure

### For Regular Production Use

**Primary**: Use **Claude Sonnet 4.6** via Anthropic API
- Best balance of performance, availability, and cost
- Proven track record in production environments
- Strong contextual understanding
- Recommended for: CI/CD integration, regular scans, most applications

### For Development/Testing

**Alternative**: Use **Claude Sonnet 3.7** or OpenAI GPT-4o
- Faster for quick feedback
- Lower cost for frequent scanning
- Good for initial triage

### Production Approach

**Tiered Strategy**:
1. **Initial Triage**: Sonnet 3.7 for fast broad scanning
2. **Deep Analysis**: Opus 4.6 for flagged areas and critical code
3. **Validation**: Multi-model consensus for high-confidence findings

**Implementation**:
- Flexible provider system (support both Anthropic and OpenAI)
- Model selection based on use case and budget
- Multi-model validation for critical codebases
- Human review required for all findings

## References

- RealVuln Benchmark (2026): https://arxiv.org/pdf/2604.13764
- Anthropic Claude Code Security Research
- XBOW Benchmark Results (May 2026)
- UK AI Security Institute (AISI) Cyber Ranges
