"""Tests for scan upload service — CycloneDX parsing and finding extraction."""

import uuid

import pytest
from fastapi import HTTPException

from app.services.scan_upload_service import _extract_findings_from_cyclonedx, _parse_cyclonedx


class TestParseCycloneDX:
    def test_valid_cyclonedx(self) -> None:
        raw = b'{"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}'
        result = _parse_cyclonedx(raw)
        assert result["bomFormat"] == "CycloneDX"

    def test_invalid_json(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _parse_cyclonedx(b"not json")
        assert exc_info.value.status_code == 400

    def test_wrong_bom_format(self) -> None:
        raw = b'{"bomFormat": "SPDX"}'
        with pytest.raises(HTTPException) as exc_info:
            _parse_cyclonedx(raw)
        assert exc_info.value.status_code == 400

    def test_missing_bom_format_ok(self) -> None:
        """If bomFormat is absent, accept it (some tools omit it)."""
        raw = b'{"specVersion": "1.7", "components": []}'
        result = _parse_cyclonedx(raw)
        assert result["specVersion"] == "1.7"


class TestExtractFindings:
    def test_basic_extraction(self) -> None:
        scan_id = uuid.uuid4()
        project_id = uuid.uuid4()
        org_id = uuid.uuid4()

        cbom = {
            "components": [
                {
                    "name": "AES-256-GCM",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": "aes"},
                    },
                    "evidence": {
                        "occurrences": [{"location": "crypto/aes.go", "line": 42}],
                    },
                    "properties": [
                        {"name": "severity", "value": "low"},
                        {"name": "confidence", "value": "high"},
                        {"name": "quantumStatus", "value": "safe"},
                        {"name": "ruleId", "value": "cbom-go-aes"},
                    ],
                },
            ]
        }

        findings = _extract_findings_from_cyclonedx(cbom, scan_id, project_id, org_id)
        assert len(findings) == 1

        f = findings[0]
        assert f.name == "AES-256-GCM"
        assert f.scan_id == scan_id
        assert f.project_id == project_id
        assert f.org_id == org_id
        assert f.asset_type == "algorithm"
        assert f.location_file == "crypto/aes.go"
        assert f.location_line == 42
        assert f.severity == "low"
        assert f.confidence == "high"
        assert f.rule_id == "cbom-go-aes"

    def test_empty_components(self) -> None:
        findings = _extract_findings_from_cyclonedx(
            {"components": []},
            uuid.uuid4(),
            uuid.uuid4(),
            uuid.uuid4(),
        )
        assert len(findings) == 0

    def test_minimal_component(self) -> None:
        findings = _extract_findings_from_cyclonedx(
            {"components": [{"name": "RSA"}]},
            uuid.uuid4(),
            uuid.uuid4(),
            uuid.uuid4(),
        )
        assert len(findings) == 1
        assert findings[0].name == "RSA"
        assert findings[0].severity == "medium"  # default
        assert findings[0].location_file == ""

    def test_multiple_components(self) -> None:
        cbom = {
            "components": [
                {"name": "AES-256"},
                {"name": "RSA-2048"},
                {"name": "SHA-256"},
            ]
        }
        findings = _extract_findings_from_cyclonedx(cbom, uuid.uuid4(), uuid.uuid4(), uuid.uuid4())
        assert len(findings) == 3
        names = {f.name for f in findings}
        assert names == {"AES-256", "RSA-2048", "SHA-256"}
