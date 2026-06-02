"""
CVE Detector configured to use Claude Opus 4.6 by default
Optimized for deep security analysis and critical applications
"""

from cve_detector import CVEDetector
from llm_client import LLMClient, LLMProvider
from model_config import AnthropicModel, print_model_comparison
import os


def create_opus_detector(
    enable_multi_model: bool = False,
    model: str = None
) -> CVEDetector:
    """
    Create a CVE detector configured with Claude Opus 4.6
    
    Args:
        enable_multi_model: Enable multi-model consensus
        model: Specific model override (default: Claude Opus 4.6)
        
    Returns:
        CVEDetector configured with Opus model
    """
    # Use Claude Opus 4.6 by default
    model = model or AnthropicModel.OPUS_4_6.value
    
    # Check for API key
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise ValueError(
            "ANTHROPIC_API_KEY not set. Claude Opus requires Anthropic API access.\n"
            "Set your API key: export ANTHROPIC_API_KEY='your-key'"
        )
    
    # Create client with Opus model
    client = LLMClient(
        provider=LLMProvider.ANTHROPIC,
        model=model
    )
    
    print(f"✓ Initialized CVE Detector with {model}")
    print(f"  Provider: Anthropic Claude")
    print(f"  Profile: Most powerful model for deep security analysis")
    print(f"  Best for: Critical applications, comprehensive audits")
    
    # Create detector
    detector = CVEDetector(
        llm_client=client,
        enable_multi_model=enable_multi_model
    )
    
    return detector


def main():
    """Example usage with Claude Opus 4.6"""
    import sys
    
    print("=" * 70)
    print("CVE Detector - Powered by Claude Opus 4.6")
    print("=" * 70)
    
    # Show model info
    print("\n📊 Model Configuration:")
    try:
        from model_config import MODEL_PROFILES
        profile = MODEL_PROFILES[AnthropicModel.OPUS_4_6.value]
        print(f"  Name: {profile.name}")
        print(f"  Accuracy: {profile.accuracy.upper()}")
        print(f"  Best For: {profile.best_for}")
        print(f"  Recommended For: {profile.recommended_for}")
    except:
        print(f"  Model: Claude Opus 4.6")
        print(f"  Accuracy: BEST")
        print(f"  Best For: Deep security analysis")
    
    print("\n" + "=" * 70)
    
    try:
        # Create Opus detector
        detector = create_opus_detector()
        
        # Get target path
        if len(sys.argv) > 1:
            target_path = sys.argv[1]
        else:
            target_path = "."
        
        print(f"\n🔍 Scanning: {target_path}")
        print("=" * 70)
        
        # Scan
        if os.path.isfile(target_path):
            print("\nMode: Single file analysis")
            result = detector.scan_file(target_path)
            
            print(f"\n{result.summary}")
            print(f"\nFound {len(result.findings)} potential vulnerabilities:\n")
            
            for i, finding in enumerate(result.findings, 1):
                print(f"{i}. [{finding.severity.upper()}] {finding.vulnerability_type}")
                print(f"   Location: {finding.location}")
                print(f"   Confidence: {finding.confidence}")
                print(f"   {finding.description[:80]}...")
                print()
        
        else:
            print("\nMode: Directory analysis")
            report = detector.scan_directory(
                target_path,
                max_files=50  # Opus can handle larger context
            )
            
            print(f"\n{report.summary}\n")
            
            # Export reports
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = f"opus_report_{timestamp}.json"
            html_file = f"opus_report_{timestamp}.html"
            
            detector.export_report(report, json_file, format='json')
            detector.export_report(report, html_file, format='html')
            
            print(f"\n✓ Reports generated:")
            print(f"  • {json_file}")
            print(f"  • {html_file}")
            
            # Show top findings
            if report.findings:
                print(f"\n🚨 Top Critical/High Findings:")
                critical_high = [
                    f for f in report.findings 
                    if f['severity'].lower() in ['critical', 'high']
                ][:5]
                
                for i, finding in enumerate(critical_high, 1):
                    print(f"\n{i}. [{finding['severity'].upper()}] {finding['vulnerability_type']}")
                    print(f"   {finding['location']}")
                    print(f"   {finding['description'][:100]}...")
    
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        print("\n💡 Troubleshooting:")
        print("  1. Ensure ANTHROPIC_API_KEY is set:")
        print("     export ANTHROPIC_API_KEY='your-key'")
        print("  2. Verify you have access to Claude Opus 4.6")
        print("  3. Check your API quota and rate limits")


if __name__ == "__main__":
    main()
