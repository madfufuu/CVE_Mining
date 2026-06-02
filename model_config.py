"""
Model configuration and selection for CVE detection
Provides easy switching between different LLM models
"""

from enum import Enum
from typing import Dict, Optional


class AnthropicModel(Enum):
    """Available Anthropic Claude models for CVE detection"""
    OPUS_4_6 = "claude-opus-4-20250514"  # Most powerful, best for deep analysis
    SONNET_4_6 = "claude-sonnet-4-20250514"  # Balanced performance/cost
    SONNET_3_7 = "claude-sonnet-3-7-20250219"  # Faster, more economical


class OpenAIModel(Enum):
    """Available OpenAI models for CVE detection"""
    GPT_4O = "gpt-4o"  # Latest, recommended
    GPT_4_TURBO = "gpt-4-turbo"  # Previous generation
    GPT_4 = "gpt-4"  # Stable, reliable


class ModelProfile:
    """Profile describing model characteristics"""
    def __init__(
        self,
        name: str,
        description: str,
        best_for: str,
        speed: str,  # fast, medium, slow
        cost: str,  # low, medium, high
        accuracy: str,  # good, better, best
        recommended_for: str
    ):
        self.name = name
        self.description = description
        self.best_for = best_for
        self.speed = speed
        self.cost = cost
        self.accuracy = accuracy
        self.recommended_for = recommended_for


# Model profiles with detailed characteristics
MODEL_PROFILES: Dict[str, ModelProfile] = {
    # Anthropic Claude Models
    AnthropicModel.OPUS_4_6.value: ModelProfile(
        name="Claude Opus 4.6",
        description="Most powerful Claude model with best-in-class reasoning",
        best_for="Deep security audits, complex codebases, legacy vulnerability detection",
        speed="slow",
        cost="high",
        accuracy="best",
        recommended_for="Critical applications, comprehensive security reviews, high-value targets"
    ),
    AnthropicModel.SONNET_4_6.value: ModelProfile(
        name="Claude Sonnet 4.6",
        description="Balanced model with excellent performance and efficiency",
        best_for="General vulnerability scanning, regular security checks",
        speed="medium",
        cost="medium",
        accuracy="better",
        recommended_for="CI/CD integration, regular scans, most production use cases"
    ),
    AnthropicModel.SONNET_3_7.value: ModelProfile(
        name="Claude Sonnet 3.7",
        description="Fast and economical model for basic scanning",
        best_for="Quick scans, large codebases, budget-conscious deployments",
        speed="fast",
        cost="low",
        accuracy="good",
        recommended_for="Initial triage, large-scale scanning, development environments"
    ),
    
    # OpenAI Models
    OpenAIModel.GPT_4O.value: ModelProfile(
        name="GPT-4o",
        description="Latest OpenAI model with strong multimodal capabilities",
        best_for="General vulnerability detection, structured analysis",
        speed="medium",
        cost="medium",
        accuracy="better",
        recommended_for="Cross-platform scanning, when Anthropic unavailable"
    ),
    OpenAIModel.GPT_4_TURBO.value: ModelProfile(
        name="GPT-4 Turbo",
        description="Previous generation with good balance",
        best_for="Standard vulnerability scanning",
        speed="medium",
        cost="medium",
        accuracy="good",
        recommended_for="Alternative to GPT-4o, proven track record"
    ),
    OpenAIModel.GPT_4.value: ModelProfile(
        name="GPT-4",
        description="Original GPT-4 with reliable performance",
        best_for="Stable, well-tested scanning",
        speed="slow",
        cost="high",
        accuracy="better",
        recommended_for="When consistency is critical"
    ),
}


def get_model_profile(model_id: str) -> Optional[ModelProfile]:
    """Get profile for a specific model"""
    return MODEL_PROFILES.get(model_id)


def print_model_comparison():
    """Print comparison table of available models"""
    print("\n" + "=" * 100)
    print("CVE Detection Models Comparison")
    print("=" * 100)
    
    print("\n🔵 ANTHROPIC CLAUDE MODELS")
    print("-" * 100)
    for model in AnthropicModel:
        profile = MODEL_PROFILES[model.value]
        print(f"\n{profile.name}")
        print(f"  Model ID: {model.value}")
        print(f"  Description: {profile.description}")
        print(f"  Best For: {profile.best_for}")
        print(f"  Speed: {profile.speed.upper()} | Cost: {profile.cost.upper()} | Accuracy: {profile.accuracy.upper()}")
        print(f"  Recommended For: {profile.recommended_for}")
    
    print("\n\n🟢 OPENAI MODELS")
    print("-" * 100)
    for model in OpenAIModel:
        profile = MODEL_PROFILES[model.value]
        print(f"\n{profile.name}")
        print(f"  Model ID: {model.value}")
        print(f"  Description: {profile.description}")
        print(f"  Best For: {profile.best_for}")
        print(f"  Speed: {profile.speed.upper()} | Cost: {profile.cost.upper()} | Accuracy: {profile.accuracy.upper()}")
        print(f"  Recommended For: {profile.recommended_for}")
    
    print("\n" + "=" * 100)


def get_recommended_model(use_case: str = "production") -> tuple[str, str]:
    """
    Get recommended model for specific use case
    
    Args:
        use_case: "production", "development", "critical", "budget"
        
    Returns:
        Tuple of (provider, model_id)
    """
    recommendations = {
        "critical": ("anthropic", AnthropicModel.OPUS_4_6.value),
        "production": ("anthropic", AnthropicModel.OPUS_4_6.value),
        "development": ("anthropic", AnthropicModel.SONNET_4_6.value),
        "budget": ("anthropic", AnthropicModel.SONNET_3_7.value),
        "fast": ("anthropic", AnthropicModel.SONNET_3_7.value),
    }
    
    return recommendations.get(use_case.lower(), ("anthropic", AnthropicModel.OPUS_4_6.value))


if __name__ == "__main__":
    print_model_comparison()
    
    print("\n\n📋 USAGE RECOMMENDATIONS")
    print("=" * 100)
    print("\n1. Critical/High-Value Applications:")
    print(f"   Use: {AnthropicModel.OPUS_4_6.value}")
    print("   Why: Best accuracy, deepest analysis, finds subtle vulnerabilities")
    
    print("\n2. Regular Production Scans:")
    print(f"   Use: {AnthropicModel.OPUS_4_6.value} or {AnthropicModel.SONNET_4_6.value}")
    print("   Why: Excellent balance of accuracy and performance")
    
    print("\n3. CI/CD Integration:")
    print(f"   Use: {AnthropicModel.SONNET_4_6.value}")
    print("   Why: Fast enough for frequent runs, still highly accurate")
    
    print("\n4. Development/Testing:")
    print(f"   Use: {AnthropicModel.SONNET_3_7.value}")
    print("   Why: Quick feedback, lower cost for frequent scans")
    
    print("\n5. Large Codebase Triage:")
    print(f"   Use: {AnthropicModel.SONNET_3_7.value} → {AnthropicModel.OPUS_4_6.value}")
    print("   Why: Fast initial scan, then deep dive on flagged areas")
    
    print("\n" + "=" * 100)
