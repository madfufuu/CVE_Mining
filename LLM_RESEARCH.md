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

### 3. **Claude Opus 4.7** (Anthropic)
- **Availability**: Enterprise/verified security teams
- **Performance**: Best-in-class for deep analysis
- **Limitations**: Higher cost, 27% repo failure rate under time constraints

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

**Primary**: Use **Claude Sonnet 4.6** via Anthropic API
- Best balance of performance, availability, and cost
- Proven track record in production environments
- Strong contextual understanding

**Alternative**: OpenAI GPT-4o or GPT-5.5
- Widely available and well-documented
- Good performance for most use cases

**Production Approach**:
- Implement flexible provider system (support both Anthropic and OpenAI)
- Consider multi-model validation for critical codebases
- Human review required for all findings

## References

- RealVuln Benchmark (2026): https://arxiv.org/pdf/2604.13764
- Anthropic Claude Code Security Research
- XBOW Benchmark Results (May 2026)
- UK AI Security Institute (AISI) Cyber Ranges
