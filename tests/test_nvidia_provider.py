import pytest
from loki.providers.nvidia_provider import NvidiaNimProvider
from loki.providers.factory import get_provider
from loki.providers.compatibility import ModelCompatibilityTester
from loki.providers.mock_provider import MockProvider


def test_nvidia_nim_initialization():
    provider = NvidiaNimProvider(
        model="meta/llama-3.3-70b-instruct",
        api_key="nvapi-testkey",
        base_url="https://integrate.api.nvidia.com/v1",
    )
    assert provider.model == "meta/llama-3.3-70b-instruct"
    assert provider.api_key == "nvapi-testkey"
    assert provider.base_url == "https://integrate.api.nvidia.com/v1"
    assert provider.supports_function_calling() is True


def test_nvidia_nim_capability_detection():
    # Known tool-calling model
    instruct_model = NvidiaNimProvider(model="mistralai/mistral-large-2-instruct")
    assert instruct_model.supports_function_calling() is True

    # Generic or custom model
    generic_model = NvidiaNimProvider(model="some/custom-completion-model")
    assert generic_model.supports_function_calling() is False


def test_factory_resolves_nvidia():
    prov = get_provider("nvidia/meta/llama-3.3-70b-instruct")
    assert isinstance(prov, NvidiaNimProvider)
    assert prov.model == "meta/llama-3.3-70b-instruct"


@pytest.mark.asyncio
async def test_compatibility_tester():
    mock = MockProvider(model="test-model")
    tester = ModelCompatibilityTester(mock)
    report = await tester.run_suite()

    assert report.model_id == "test-model"
    assert len(report.tests) >= 2
    # Mock supports basic text and streaming
    basic_test = next(t for t in report.tests if "Basic" in t.name)
    assert basic_test.passed is True
