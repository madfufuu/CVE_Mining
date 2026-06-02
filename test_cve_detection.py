"""
Tests for LLM-based CVE detection system
"""

import os
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from llm_client import (
    LLMClient,
    LLMProvider,
    VulnerabilityFinding,
    AnalysisResult,
    get_recommended_client
)
from cve_detector import CVEDetector, CVEDetectionReport


# Sample vulnerable code for testing
VULNERABLE_SQL_CODE = """
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""

VULNERABLE_XSS_CODE = """
@app.route('/search')
def search():
    query = request.args.get('q')
    return '<h1>Results for: ' + query + '</h1>'
"""

SAFE_CODE = """
def add_numbers(a, b):
    return a + b
"""

# Mock LLM responses
MOCK_VULNERABILITY_RESPONSE = """{
  "summary": "Found 1 SQL injection vulnerability",
  "findings": [
    {
      "severity": "critical",
      "vulnerability_type": "SQL Injection",
      "description": "User input is directly concatenated into SQL query without sanitization",
      "location": "test.py:lines 2-4",
      "affected_code": "query = \\"SELECT * FROM users WHERE username = '\\" + username + \\"'\\"",
      "recommendation": "Use parameterized queries or ORM",
      "cwe_id": "CWE-89",
      "confidence": "high"
    }
  ]
}"""

MOCK_NO_VULNERABILITY_RESPONSE = """{
  "summary": "No vulnerabilities found",
  "findings": []
}"""


class TestLLMClient:
    """Test LLM client functionality"""
    
    def test_llm_client_initialization_anthropic(self):
        """Test Anthropic client initialization"""
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            with patch('llm_client.anthropic.Anthropic'):
                client = LLMClient(provider=LLMProvider.ANTHROPIC)
                assert client.provider == LLMProvider.ANTHROPIC
                assert client.model == "claude-sonnet-4-20250514"
    
    def test_llm_client_initialization_openai(self):
        """Test OpenAI client initialization"""
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            with patch('llm_client.openai.OpenAI'):
                client = LLMClient(provider=LLMProvider.OPENAI)
                assert client.provider == LLMProvider.OPENAI
                assert client.model == "gpt-4o"
    
    def test_missing_api_key(self):
        """Test error when API key is missing"""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="API_KEY"):
                LLMClient(provider=LLMProvider.ANTHROPIC)
    
    def test_get_recommended_client_anthropic(self):
        """Test recommended client selection with Anthropic key"""
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            with patch('llm_client.anthropic.Anthropic'):
                client = get_recommended_client()
                assert client.provider == LLMProvider.ANTHROPIC
    
    def test_get_recommended_client_openai_fallback(self):
        """Test fallback to OpenAI when Anthropic key not available"""
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}, clear=True):
            with patch('llm_client.openai.OpenAI'):
                client = get_recommended_client()
                assert client.provider == LLMProvider.OPENAI
    
    def test_get_recommended_client_no_keys(self):
        """Test error when no API keys available"""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="No API keys found"):
                get_recommended_client()
    
    @patch('llm_client.anthropic.Anthropic')
    def test_analyze_code_anthropic(self, mock_anthropic):
        """Test code analysis with Anthropic"""
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            # Mock response
            mock_response = Mock()
            mock_response.content = [Mock(text=MOCK_VULNERABILITY_RESPONSE)]
            mock_client_instance = Mock()
            mock_client_instance.messages.create.return_value = mock_response
            mock_anthropic.return_value = mock_client_instance
            
            client = LLMClient(provider=LLMProvider.ANTHROPIC)
            result = client.analyze_code(
                code=VULNERABLE_SQL_CODE,
                file_path="test.py",
                language="python"
            )
            
            assert isinstance(result, AnalysisResult)
            assert len(result.findings) == 1
            assert result.findings[0].vulnerability_type == "SQL Injection"
            assert result.findings[0].severity == "critical"
    
    @patch('llm_client.openai.OpenAI')
    def test_analyze_code_openai(self, mock_openai):
        """Test code analysis with OpenAI"""
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            # Mock response
            mock_response = Mock()
            mock_response.choices = [Mock(message=Mock(content=MOCK_VULNERABILITY_RESPONSE))]
            mock_client_instance = Mock()
            mock_client_instance.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client_instance
            
            client = LLMClient(provider=LLMProvider.OPENAI)
            result = client.analyze_code(
                code=VULNERABLE_SQL_CODE,
                file_path="test.py",
                language="python"
            )
            
            assert isinstance(result, AnalysisResult)
            assert len(result.findings) == 1
    
    @patch('llm_client.anthropic.Anthropic')
    def test_analyze_code_no_vulnerabilities(self, mock_anthropic):
        """Test analysis when no vulnerabilities found"""
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            mock_response = Mock()
            mock_response.content = [Mock(text=MOCK_NO_VULNERABILITY_RESPONSE)]
            mock_client_instance = Mock()
            mock_client_instance.messages.create.return_value = mock_response
            mock_anthropic.return_value = mock_client_instance
            
            client = LLMClient(provider=LLMProvider.ANTHROPIC)
            result = client.analyze_code(
                code=SAFE_CODE,
                file_path="safe.py",
                language="python"
            )
            
            assert len(result.findings) == 0
            assert "No vulnerabilities" in result.summary
    
    def test_vulnerability_finding_dataclass(self):
        """Test VulnerabilityFinding dataclass"""
        finding = VulnerabilityFinding(
            severity="high",
            vulnerability_type="XSS",
            description="Cross-site scripting vulnerability",
            location="app.py:10",
            affected_code="return html",
            recommendation="Use proper escaping",
            cwe_id="CWE-79",
            confidence="high"
        )
        
        assert finding.severity == "high"
        assert finding.vulnerability_type == "XSS"
        assert finding.cwe_id == "CWE-79"


class TestCVEDetector:
    """Test CVE detector functionality"""
    
    @patch('cve_detector.get_recommended_client')
    def test_detector_initialization(self, mock_get_client):
        """Test CVE detector initialization"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        detector = CVEDetector()
        assert detector.primary_client == mock_client
        assert not detector.enable_multi_model
    
    @patch('cve_detector.get_recommended_client')
    def test_detector_multi_model_initialization(self, mock_get_client):
        """Test multi-model detector initialization"""
        mock_client = Mock()
        mock_client.provider = LLMProvider.ANTHROPIC
        mock_get_client.return_value = mock_client
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            with patch('cve_detector.LLMClient') as mock_llm_client:
                detector = CVEDetector(enable_multi_model=True)
                assert detector.enable_multi_model
    
    def test_detect_language(self):
        """Test language detection from file extension"""
        detector = CVEDetector.__new__(CVEDetector)
        
        assert detector._detect_language("test.py") == "python"
        assert detector._detect_language("app.js") == "javascript"
        assert detector._detect_language("main.go") == "go"
        assert detector._detect_language("code.unknown") == "unknown"
    
    @patch('cve_detector.get_recommended_client')
    def test_scan_file(self, mock_get_client, tmp_path):
        """Test scanning a single file"""
        # Create temporary file
        test_file = tmp_path / "test.py"
        test_file.write_text(VULNERABLE_SQL_CODE)
        
        # Mock client
        mock_client = Mock()
        mock_result = AnalysisResult(
            findings=[
                VulnerabilityFinding(
                    severity="critical",
                    vulnerability_type="SQL Injection",
                    description="SQL injection vulnerability",
                    location=f"{test_file}:2",
                    affected_code="query =",
                    recommendation="Use parameterized queries",
                    cwe_id="CWE-89",
                    confidence="high"
                )
            ],
            summary="Found 1 vulnerability",
            total_files_analyzed=1,
            model_used="test-model",
            provider="test"
        )
        mock_client.analyze_code.return_value = mock_result
        mock_get_client.return_value = mock_client
        
        detector = CVEDetector()
        result = detector.scan_file(str(test_file))
        
        assert len(result.findings) == 1
        assert result.findings[0].vulnerability_type == "SQL Injection"
    
    @patch('cve_detector.get_recommended_client')
    def test_scan_nonexistent_file(self, mock_get_client):
        """Test error when scanning nonexistent file"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        detector = CVEDetector()
        
        with pytest.raises(FileNotFoundError):
            detector.scan_file("nonexistent.py")
    
    @patch('cve_detector.get_recommended_client')
    def test_generate_report(self, mock_get_client):
        """Test report generation"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        detector = CVEDetector()
        
        findings = [
            VulnerabilityFinding(
                severity="critical",
                vulnerability_type="SQL Injection",
                description="Test",
                location="test.py:10",
                affected_code="code",
                recommendation="fix it",
                confidence="high"
            ),
            VulnerabilityFinding(
                severity="high",
                vulnerability_type="XSS",
                description="Test",
                location="test.py:20",
                affected_code="code",
                recommendation="fix it",
                confidence="medium"
            )
        ]
        
        report = detector._generate_report(
            repo_path="/test/path",
            files_count=2,
            findings=findings,
            models_used=["anthropic/claude"]
        )
        
        assert isinstance(report, CVEDetectionReport)
        assert report.files_analyzed == 2
        assert report.vulnerabilities_found == 2
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 0
        assert report.low_count == 0
    
    @patch('cve_detector.get_recommended_client')
    def test_export_report_json(self, mock_get_client, tmp_path):
        """Test JSON report export"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        detector = CVEDetector()
        
        report = CVEDetectionReport(
            timestamp="2026-06-02T00:00:00",
            repository_path="/test",
            files_analyzed=1,
            vulnerabilities_found=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            findings=[{
                "severity": "critical",
                "vulnerability_type": "Test",
                "description": "Test vuln",
                "location": "test.py:1",
                "affected_code": "code",
                "recommendation": "fix",
                "cwe_id": None,
                "confidence": "high"
            }],
            summary="Test summary",
            models_used=["test-model"]
        )
        
        output_file = tmp_path / "report.json"
        detector.export_report(report, str(output_file), format='json')
        
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert data['vulnerabilities_found'] == 1
    
    @patch('cve_detector.get_recommended_client')
    def test_export_report_html(self, mock_get_client, tmp_path):
        """Test HTML report export"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        detector = CVEDetector()
        
        report = CVEDetectionReport(
            timestamp="2026-06-02T00:00:00",
            repository_path="/test",
            files_analyzed=1,
            vulnerabilities_found=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            findings=[{
                "severity": "critical",
                "vulnerability_type": "Test",
                "description": "Test vuln",
                "location": "test.py:1",
                "affected_code": "code",
                "recommendation": "fix",
                "cwe_id": "CWE-89",
                "confidence": "high"
            }],
            summary="Test summary",
            models_used=["test-model"]
        )
        
        output_file = tmp_path / "report.html"
        detector.export_report(report, str(output_file), format='html')
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "CVE Detection Report" in content
        assert "Test vuln" in content


class TestIntegration:
    """Integration tests (require actual API keys)"""
    
    @pytest.mark.skipif(
        not os.getenv('ANTHROPIC_API_KEY') and not os.getenv('OPENAI_API_KEY'),
        reason="No API keys available for integration testing"
    )
    def test_real_vulnerability_detection(self, tmp_path):
        """Test real vulnerability detection with actual LLM"""
        # Create test file with known vulnerability
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text(VULNERABLE_SQL_CODE)
        
        # Run detector
        detector = CVEDetector()
        result = detector.scan_file(str(test_file))
        
        # Should detect SQL injection
        assert len(result.findings) > 0
        # Check if any finding is about SQL injection
        sql_findings = [
            f for f in result.findings 
            if 'sql' in f.vulnerability_type.lower() or 'injection' in f.vulnerability_type.lower()
        ]
        assert len(sql_findings) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
