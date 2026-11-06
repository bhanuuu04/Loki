import pytest
from loki.cli.doctor import LokiDoctor


@pytest.mark.asyncio
async def test_doctor_diagnostic_suite():
    items = await LokiDoctor.run_diagnostics()
    assert len(items) >= 5

    categories = {it.category for it in items}
    assert "System" in categories
    assert "Dependencies" in categories
    assert "Execution" in categories
    assert "Storage" in categories

    # All items should have valid PASS, WARN, or FAIL status
    for it in items:
        assert it.status in ("PASS", "WARN", "FAIL")
