"""Tests for SBOM service — parsing, format detection, component extraction."""

import pytest

from app.services.sbom_service import (
    _detect_sbom_format,
    _extract_components,
    _extract_components_cyclonedx,
    _extract_components_spdx,
)


class TestFormatDetection:
    def test_cyclonedx_explicit(self) -> None:
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        assert _detect_sbom_format(sbom) == "cyclonedx"

    def test_spdx_explicit(self) -> None:
        sbom = {"spdxVersion": "SPDX-2.3", "packages": []}
        assert _detect_sbom_format(sbom) == "spdx"

    def test_cyclonedx_heuristic(self) -> None:
        sbom = {"components": [{"name": "openssl"}]}
        assert _detect_sbom_format(sbom) == "cyclonedx"

    def test_spdx_heuristic(self) -> None:
        sbom = {"packages": [{"name": "openssl"}]}
        assert _detect_sbom_format(sbom) == "spdx"

    def test_unknown_format_raises(self) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _detect_sbom_format({"foo": "bar"})
        assert exc_info.value.status_code == 400


class TestCycloneDXExtraction:
    def test_extract_basic_components(self) -> None:
        sbom = {
            "components": [
                {"name": "openssl", "version": "3.0.2", "purl": "pkg:generic/openssl@3.0.2", "type": "library"},
                {"name": "libsodium", "version": "1.0.18"},
            ]
        }
        components = _extract_components_cyclonedx(sbom)
        assert len(components) == 2
        assert components[0].name == "openssl"
        assert components[0].version == "3.0.2"
        assert components[0].purl == "pkg:generic/openssl@3.0.2"
        assert components[1].name == "libsodium"

    def test_skip_empty_name(self) -> None:
        sbom = {"components": [{"name": "", "version": "1.0"}, {"name": "valid"}]}
        components = _extract_components_cyclonedx(sbom)
        assert len(components) == 1
        assert components[0].name == "valid"

    def test_empty_components(self) -> None:
        sbom = {"components": []}
        components = _extract_components_cyclonedx(sbom)
        assert len(components) == 0


class TestSPDXExtraction:
    def test_extract_basic_packages(self) -> None:
        sbom = {
            "packages": [
                {
                    "name": "openssl",
                    "versionInfo": "3.0.2",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:generic/openssl@3.0.2"},
                    ],
                },
                {"name": "boringssl", "versionInfo": "1.0"},
            ]
        }
        components = _extract_components_spdx(sbom)
        assert len(components) == 2
        assert components[0].name == "openssl"
        assert components[0].purl == "pkg:generic/openssl@3.0.2"
        assert components[1].name == "boringssl"
        assert components[1].purl is None


class TestExtractComponents:
    def test_dispatch_cyclonedx(self) -> None:
        sbom = {"components": [{"name": "test-lib", "version": "1.0"}]}
        components = _extract_components(sbom, "cyclonedx")
        assert len(components) == 1

    def test_dispatch_spdx(self) -> None:
        sbom = {"packages": [{"name": "test-lib", "versionInfo": "1.0"}]}
        components = _extract_components(sbom, "spdx")
        assert len(components) == 1

    def test_dispatch_unknown(self) -> None:
        components = _extract_components({}, "unknown")
        assert len(components) == 0
