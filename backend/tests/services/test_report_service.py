"""Tests for report generation service."""

import pytest

from app.services.report_service import (
    generate_csv_report,
    generate_html_report,
    generate_pdf_report,
)

# Sample scan data for testing
_SAMPLE_FINDINGS = [
    {
        "name": "RSA-2048 key generation",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "vulnerable",
        "asset_type": "asymmetric-key",
        "location_file": "src/crypto/keys.py",
        "location_line": 42,
        "rule_id": "cbom-python-rsa",
    },
    {
        "name": "AES-256-GCM encryption",
        "severity": "low",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "symmetric-key",
        "location_file": "src/crypto/encrypt.py",
        "location_line": 15,
        "rule_id": "cbom-python-aes",
    },
]

_SAMPLE_SCAN_DATA = {
    "scan_id": "00000000-0000-0000-0000-000000000001",
    "findings": _SAMPLE_FINDINGS,
    "quantum_risk": {
        "score": 35.0,
        "vulnerable_count": 1,
        "safe_count": 1,
        "broken_count": 0,
        "migration_items": [
            {
                "algorithm": "rsa",
                "count": 1,
                "severity": "high",
                "migrate_to": "ml-dsa",
                "priority": 1,
            },
        ],
    },
    "compliance": [
        {
            "framework": "nist-800-131a",
            "score": 83.3,
            "compliant_count": 1,
            "non_compliant_count": 1,
            "items": [
                {
                    "algorithm": "rsa",
                    "classification": "deprecated",
                    "count": 1,
                    "note": "RSA with key size >= 2048 is deprecated",
                    "action_required": "schedule-migration",
                },
            ],
        },
        {
            "framework": "fips-140-3",
            "score": 100.0,
            "compliant_count": 2,
            "non_compliant_count": 0,
            "items": [],
        },
    ],
}


@pytest.mark.asyncio
async def test_generate_pdf_quantum_readiness_returns_pdf_bytes() -> None:
    """PDF generation for quantum-readiness should return bytes starting with %PDF."""
    result = await generate_pdf_report(
        "00000000-0000-0000-0000-000000000001",
        "quantum-readiness",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, bytes)
    assert result[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_generate_pdf_compliance_gap_returns_pdf_bytes() -> None:
    """PDF generation for compliance-gap should return bytes starting with %PDF."""
    result = await generate_pdf_report(
        "00000000-0000-0000-0000-000000000001",
        "compliance-gap",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, bytes)
    assert result[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_generate_pdf_findings_summary_returns_pdf_bytes() -> None:
    """PDF generation for findings-summary should return bytes starting with %PDF."""
    result = await generate_pdf_report(
        "00000000-0000-0000-0000-000000000001",
        "findings-summary",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, bytes)
    assert result[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_generate_pdf_invalid_type_raises() -> None:
    """Unknown report type should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown report type"):
        await generate_pdf_report("scan-1", "nonexistent", {})


@pytest.mark.asyncio
async def test_generate_html_quantum_readiness_contains_expected_elements() -> None:
    """HTML quantum-readiness report should contain key elements."""
    result = await generate_html_report(
        "00000000-0000-0000-0000-000000000001",
        "quantum-readiness",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, str)
    assert "Quantum Readiness Report" in result
    assert "00000000-0000-0000-0000-000000000001" in result
    assert "Migration Priorities" in result
    assert "rsa" in result
    assert "ml-dsa" in result


@pytest.mark.asyncio
async def test_generate_html_compliance_gap_contains_expected_elements() -> None:
    """HTML compliance-gap report should contain framework names and scores."""
    result = await generate_html_report(
        "00000000-0000-0000-0000-000000000001",
        "compliance-gap",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, str)
    assert "Compliance Gap Report" in result
    assert "nist-800-131a" in result
    assert "fips-140-3" in result


@pytest.mark.asyncio
async def test_generate_html_findings_summary_contains_expected_elements() -> None:
    """HTML findings-summary report should contain findings table."""
    result = await generate_html_report(
        "00000000-0000-0000-0000-000000000001",
        "findings-summary",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, str)
    assert "Findings Summary Report" in result
    assert "RSA-2048 key generation" in result
    assert "AES-256-GCM encryption" in result


@pytest.mark.asyncio
async def test_generate_html_invalid_type_raises() -> None:
    """Unknown report type should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown report type"):
        await generate_html_report("scan-1", "nonexistent", {})


@pytest.mark.asyncio
async def test_generate_csv_has_correct_headers() -> None:
    """CSV report should have the expected header row."""
    result = await generate_csv_report(
        "00000000-0000-0000-0000-000000000001",
        _SAMPLE_SCAN_DATA.copy(),
    )
    assert isinstance(result, str)

    lines = result.strip().split("\n")
    assert len(lines) >= 1  # at least the header

    header = lines[0]
    expected_fields = [
        "scan_id",
        "name",
        "severity",
        "confidence",
        "quantum_status",
        "asset_type",
        "location_file",
        "location_line",
        "rule_id",
    ]
    for field in expected_fields:
        assert field in header


@pytest.mark.asyncio
async def test_generate_csv_has_correct_row_count() -> None:
    """CSV should have one header row plus one row per finding."""
    result = await generate_csv_report(
        "00000000-0000-0000-0000-000000000001",
        _SAMPLE_SCAN_DATA.copy(),
    )
    lines = result.strip().split("\n")
    # 1 header + 2 findings
    assert len(lines) == 3


@pytest.mark.asyncio
async def test_generate_csv_empty_findings() -> None:
    """CSV with no findings should still have the header."""
    result = await generate_csv_report("scan-1", {"findings": []})
    lines = result.strip().split("\n")
    assert len(lines) == 1  # just the header
