"""
LLM Client for CVE Detection
Supports multiple LLM providers for vulnerability analysis
"""

import os
import json
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Import model configurations if available
try:
    from model_config import AnthropicModel, OpenAIModel, get_model_profile
except ImportError:
    # Fallback if model_config not available
    class AnthropicModel:
        OPUS_4_6 = "claude-opus-4-20250514"
        SONNET_4_6 = "claude-sonnet-4-20250514"
    class OpenAIModel:
        GPT_4O = "gpt-4o"


class LLMProvider(Enum):
    """Supported LLM providers"""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding from LLM analysis"""
    severity: str  # critical, high, medium, low
    vulnerability_type: str  # e.g., SQL Injection, XSS, etc.
    description: str
    location: str  # file path and line numbers
    affected_code: str
    recommendation: str
    cwe_id: Optional[str] = None
    confidence: str = "medium"  # high, medium, low


@dataclass
class AnalysisResult:
    """Complete analysis result from LLM"""
    findings: List[VulnerabilityFinding]
    summary: str
    total_files_analyzed: int
    model_used: str
    provider: str


class LLMClient:
    """
    Multi-provider LLM client for code vulnerability analysis
    Supports Anthropic Claude and OpenAI GPT models
    """
    
    def __init__(
        self,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        """
        Initialize LLM client
        
        Args:
            provider: LLM provider to use (Anthropic or OpenAI)
            api_key: API key (if None, will use environment variables)
            model: Specific model to use (if None, uses recommended default)
        """
        self.provider = provider
        self.api_key = api_key or self._get_api_key()
        self.model = model or self._get_default_model()
        self.client = self._initialize_client()
    
    def _get_api_key(self) -> str:
        """Get API key from environment variables"""
        if self.provider == LLMProvider.ANTHROPIC:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY environment variable not set. "
                    "Please set it or pass api_key parameter."
                )
            return api_key
        elif self.provider == LLMProvider.OPENAI:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError(
                    "OPENAI_API_KEY environment variable not set. "
                    "Please set it or pass api_key parameter."
                )
            return api_key
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _get_default_model(self) -> str:
        """Get recommended default model for each provider"""
        if self.provider == LLMProvider.ANTHROPIC:
            # Claude Opus 4.6 - Most powerful for deep security analysis
            # Alternative: "claude-sonnet-4-20250514" for faster/cheaper scans
            return "claude-opus-4-20250514"  # Claude Opus 4.6
        elif self.provider == LLMProvider.OPENAI:
            return "gpt-4o"  # GPT-4o
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _initialize_client(self):
        """Initialize the appropriate SDK client"""
        if self.provider == LLMProvider.ANTHROPIC:
            try:
                import anthropic
                return anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "anthropic package not installed. "
                    "Install it with: pip install anthropic"
                )
        elif self.provider == LLMProvider.OPENAI:
            try:
                import openai
                return openai.OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "openai package not installed. "
                    "Install it with: pip install openai"
                )
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def analyze_code(
        self,
        code: str,
        file_path: str = "unknown",
        language: str = "python",
        context: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze code for security vulnerabilities
        
        Args:
            code: Source code to analyze
            file_path: Path to the file being analyzed
            language: Programming language of the code
            context: Additional context about the codebase
            
        Returns:
            AnalysisResult containing vulnerability findings
        """
        prompt = self._build_vulnerability_prompt(code, file_path, language, context)
        
        if self.provider == LLMProvider.ANTHROPIC:
            response = self._call_anthropic(prompt)
        elif self.provider == LLMProvider.OPENAI:
            response = self._call_openai(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
        
        return self._parse_analysis_response(response, file_path)
    
    def analyze_multiple_files(
        self,
        files: Dict[str, str],
        language: str = "python"
    ) -> AnalysisResult:
        """
        Analyze multiple files for vulnerabilities
        
        Args:
            files: Dict mapping file paths to their contents
            language: Programming language of the files
            
        Returns:
            AnalysisResult containing all findings across files
        """
        prompt = self._build_multi_file_prompt(files, language)
        
        if self.provider == LLMProvider.ANTHROPIC:
            response = self._call_anthropic(prompt)
        elif self.provider == LLMProvider.OPENAI:
            response = self._call_openai(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
        
        return self._parse_analysis_response(response, "multiple_files", len(files))
    
    def _build_vulnerability_prompt(
        self,
        code: str,
        file_path: str,
        language: str,
        context: Optional[str] = None
    ) -> str:
        """Build the prompt for vulnerability analysis"""
        base_prompt = f"""You are a security expert analyzing code for vulnerabilities. Perform a comprehensive security analysis of the following {language} code.

FILE: {file_path}

CODE:
```{language}
{code}
```

{f'CONTEXT: {context}' if context else ''}

Analyze this code for security vulnerabilities including but not limited to:
- Injection vulnerabilities (SQL, Command, XSS, etc.)
- Authentication and authorization issues
- Cryptographic weaknesses
- Insecure deserialization
- Security misconfigurations
- Exposed sensitive data
- Insufficient logging and monitoring
- Using components with known vulnerabilities
- Race conditions and concurrency issues
- Memory safety issues (if applicable)

For each vulnerability found, provide:
1. Severity (critical/high/medium/low)
2. Vulnerability type (e.g., SQL Injection)
3. Detailed description
4. Exact location (line numbers)
5. The vulnerable code snippet
6. Recommendation for fixing
7. CWE ID if applicable
8. Confidence level (high/medium/low)

Respond ONLY with valid JSON in this exact format:
{{
  "summary": "Brief summary of findings",
  "findings": [
    {{
      "severity": "high",
      "vulnerability_type": "SQL Injection",
      "description": "Detailed description",
      "location": "filename.py:lines 10-15",
      "affected_code": "code snippet",
      "recommendation": "How to fix",
      "cwe_id": "CWE-89",
      "confidence": "high"
    }}
  ]
}}

If no vulnerabilities are found, return an empty findings array."""
        
        return base_prompt
    
    def _build_multi_file_prompt(self, files: Dict[str, str], language: str) -> str:
        """Build prompt for analyzing multiple files"""
        files_section = ""
        for file_path, content in files.items():
            files_section += f"\n\nFILE: {file_path}\n```{language}\n{content}\n```\n"
        
        prompt = f"""You are a security expert analyzing a codebase for vulnerabilities. Perform a comprehensive security analysis of the following {language} files.

{files_section}

Analyze these files for security vulnerabilities including:
- Injection vulnerabilities (SQL, Command, XSS, etc.)
- Authentication and authorization issues
- Cryptographic weaknesses
- Insecure deserialization
- Security misconfigurations
- Exposed sensitive data
- Cross-file security issues
- API security problems
- Data flow vulnerabilities

For each vulnerability found, provide:
1. Severity (critical/high/medium/low)
2. Vulnerability type
3. Detailed description
4. Exact location (file and line numbers)
5. The vulnerable code snippet
6. Recommendation for fixing
7. CWE ID if applicable
8. Confidence level (high/medium/low)

Respond ONLY with valid JSON in this exact format:
{{
  "summary": "Brief summary of findings",
  "findings": [
    {{
      "severity": "high",
      "vulnerability_type": "SQL Injection",
      "description": "Detailed description",
      "location": "filename.py:lines 10-15",
      "affected_code": "code snippet",
      "recommendation": "How to fix",
      "cwe_id": "CWE-89",
      "confidence": "high"
    }}
  ]
}}

If no vulnerabilities are found, return an empty findings array."""
        
        return prompt
    
    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic API"""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        except Exception as e:
            raise RuntimeError(f"Anthropic API error: {str(e)}")
    
    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert specializing in code vulnerability analysis."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4096,
                temperature=0.1  # Lower temperature for more consistent results
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {str(e)}")
    
    def _parse_analysis_response(
        self,
        response: str,
        file_path: str,
        file_count: int = 1
    ) -> AnalysisResult:
        """Parse the LLM response into structured findings"""
        try:
            # Extract JSON from response (in case there's extra text)
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON found in response")
            
            json_str = response[json_start:json_end]
            data = json.loads(json_str)
            
            findings = []
            for finding_data in data.get("findings", []):
                finding = VulnerabilityFinding(
                    severity=finding_data.get("severity", "unknown"),
                    vulnerability_type=finding_data.get("vulnerability_type", "unknown"),
                    description=finding_data.get("description", ""),
                    location=finding_data.get("location", file_path),
                    affected_code=finding_data.get("affected_code", ""),
                    recommendation=finding_data.get("recommendation", ""),
                    cwe_id=finding_data.get("cwe_id"),
                    confidence=finding_data.get("confidence", "medium")
                )
                findings.append(finding)
            
            return AnalysisResult(
                findings=findings,
                summary=data.get("summary", "Analysis complete"),
                total_files_analyzed=file_count,
                model_used=self.model,
                provider=self.provider.value
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse LLM response as JSON: {str(e)}\nResponse: {response}")
        except Exception as e:
            raise ValueError(f"Error parsing analysis response: {str(e)}")


def get_recommended_client() -> LLMClient:
    """
    Get a client with recommended settings for vulnerability detection
    Based on 2026 research, Claude Sonnet 4.6 is recommended for best results
    """
    # Try Anthropic first (recommended)
    if os.getenv("ANTHROPIC_API_KEY"):
        return LLMClient(provider=LLMProvider.ANTHROPIC)
    # Fall back to OpenAI
    elif os.getenv("OPENAI_API_KEY"):
        return LLMClient(provider=LLMProvider.OPENAI)
    else:
        raise ValueError(
            "No API keys found. Please set either ANTHROPIC_API_KEY or OPENAI_API_KEY "
            "environment variable. Anthropic Claude is recommended based on 2026 research."
        )
