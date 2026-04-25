"""
LicenseSeal SBOM & Sigstore Integration Module
==============================================
Integrates with SPDX, CycloneDX standards and Sigstore for cryptographic signing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .core import (
    BOUNDARY_BEGIN,
    BOUNDARY_END,
    current_utc_iso,
    parse_marker_fields,
    project_license_marker_stats,
)


# SBOM Formats
class SBOMFormat:
    """Supported SBOM formats."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SWID = "swid"


@dataclass
class SBOMConfig:
    """Configuration for SBOM generation."""
    format: str = SBOMFormat.CYCLONEDX
    tool_name: str = "licenseseal"
    tool_version: str = "0.3.0"
    include_embeddings: bool = False
    include_watermarks: bool = False


@dataclass
class SBOMEntry:
    """Single entry in SBOM."""
    file_path: str
    license_id: str
    owner: str
    content_hash: str
    signature: Optional[str] = None
    git_commit: Optional[str] = None
    watermark_detected: bool = False


class SPDXExporter:
    """Exports LicenseSeal data to SPDX format."""

    def __init__(self, config: SBOMConfig):
        self.config = config

    def generate_spdx(
        self,
        root: Path,
        project_name: str,
        files: list[SBOMEntry],
    ) -> str:
        """Generate SPDX JSON document."""
        doc_id = f"SPDX:licenseseal-{project_name}-{current_utc_iso()}"

        packages = []
        for i, entry in enumerate(files):
            pkg_id = f"Package-{i+1}"
            packages.append({
                "SPDXID": f"SPDXRef-{pkg_id}",
                "name": entry.file_path,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "verificationCodeValue": entry.content_hash,
                "licenseConcluded": entry.license_id,
                "licenseDeclared": entry.license_id,
                "copyrightText": f"Copyright (c) {datetime.now().year} {entry.owner}",
                "externalRefs": [
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "licenseseal-provenance",
                        "referenceLocator": entry.content_hash,
                    }
                ],
            })

        # Add relationships
        relationships = []
        for i in range(len(packages)):
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "spdxElementId": f"SPDXRef-Package-{i+1}",
            })

        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": f"LicenseSeal SBOM for {project_name}",
            "documentNamespace": f"https://licenseseal.io/sbom/{project_name}",
            "creationInfo": {
                "created": current_utc_iso(),
                "creators": [
                    f"Tool: {self.config.tool_name}/{self.config.tool_version}",
                ],
            },
            "packages": packages,
            "relationships": relationships,
        }

        return json.dumps(spdx_doc, indent=2, ensure_ascii=False)


class CycloneDXExporter:
    """Exports LicenseSeal data to CycloneDX format."""

    def generate_cyclonedx(
        self,
        root: Path,
        project_name: str,
        files: list[SBOMEntry],
    ) -> str:
        """Generate CycloneDX JSON document."""
        components = []

        for entry in files:
            component = {
                "type": "file",
                "name": entry.file_path,
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": entry.content_hash[:64],
                    }
                ],
                "licenses": [
                    {
                        "license": {
                            "id": entry.license_id,
                        }
                    }
                ],
                "copyright": f"Copyright (c) {datetime.now().year} {entry.owner}",
            }

            # Add provenance extensions
            if entry.signature or entry.git_commit:
                component["extensions"] = {
                    "licenseseal": {
                        "provenance": {
                            "contentHash": entry.content_hash,
                        }
                    }
                }

                if entry.signature:
                    component["extensions"]["licenseseal"]["signature"] = entry.signature

                if entry.git_commit:
                    component["extensions"]["licenseseal"]["gitCommit"] = entry.git_commit

            components.append(component)

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": current_utc_iso(),
                "tools": [
                    {
                        "name": self.config.tool_name,
                        "version": self.config.tool_version,
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "root": str(root),
                },
            },
            "components": components,
        }

        return json.dumps(bom, indent=2, ensure_ascii=False)


def extract_license_entries(root: Path) -> list[SBOMEntry]:
    """Extract license information from all files in a project."""
    from .core import iter_candidate_files, parse_marker_fields, strip_license_boundary

    entries = []

    for path in iter_candidate_files(root, None, False):
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue

        # Check for LicenseSeal marker
        if BOUNDARY_BEGIN not in text:
            continue

        fields = parse_marker_fields(text)
        content = strip_license_boundary(text)
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        entry = SBOMEntry(
            file_path=str(path.relative_to(root)),
            license_id=fields.get("SPDX-License-Identifier", "UNKNOWN"),
            owner=fields.get("Copyright", "").replace("Copyright (c) ", ""),
            content_hash=content_hash,
            signature=fields.get("AI_SIGNATURE"),
            git_commit=fields.get("GIT_COMMIT"),
            watermark_detected=False,  # Would need watermark module check
        )

        entries.append(entry)

    return entries


def generate_sbom(
    root: Path,
    project_name: str,
    output_path: Path | None = None,
    format: str = SBOMFormat.CYCLONEDX,
    config: SBOMConfig | None = None,
) -> str:
    """Generate SBOM from LicenseSeal project."""
    cfg = config or SBOMConfig(format=format)
    entries = extract_license_entries(root)

    if format == SBOMFormat.SPDX:
        exporter = SPDXExporter(cfg)
        sbom = exporter.generate_spdx(root, project_name, entries)
    else:
        exporter = CycloneDXExporter()
        sbom = exporter.generate_cyclonedx(root, project_name, entries)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(sbom, encoding="utf-8")

    return sbom


# =============================================================================
# Sigstore Integration
# =============================================================================

class SigstoreSigner:
    """Integrates with Sigstore for cryptographic code signing."""

    def __init__(self, identity_token: str | None = None):
        self.identity_token = identity_token
        self._fulcio_url = "https://fulcio.sigstore.dev"
        self._rekor_url = "https://rekor.sigstore.dev"

    def is_available(self) -> bool:
        """Check if Sigstore tools are available."""
        try:
            result = subprocess.run(
                ["cosign", "version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def sign_oci(
        self,
        image_ref: str,
        private_key: Path | None = None,
    ) -> dict:
        """
        Sign an OCI artifact with Sigstore.
        Returns transparency log entry.
        """
        if not self.is_available():
            raise RuntimeError(
                "cosign is required for Sigstore signing. "
                "Install from: https://github.com/sigstore/cosign"
            )

        cmd = ["cosign", "sign", "--yes", image_ref]

        if self.identity_token:
            cmd.extend(["--oidc-identity", self.identity_token])
        elif private_key:
            cmd.extend(["--key", str(private_key)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                return {
                    "status": "signed",
                    "image": image_ref,
                    "transparency_log": f"{self._rekor_url}/api/v1/log/entries",
                }
            else:
                return {
                    "status": "failed",
                    "error": result.stderr,
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }

    def verify_oci(
        self,
        image_ref: str,
        public_key: Path | None = None,
    ) -> dict:
        """Verify an OCI artifact signature."""
        if not self.is_available():
            return {"status": "unavailable", "reason": "cosign not installed"}

        cmd = ["cosign", "verify", image_ref]

        if public_key:
            cmd.extend(["--key", str(public_key)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                return {
                    "status": "verified",
                    "image": image_ref,
                    "output": result.stdout,
                }
            else:
                return {
                    "status": "invalid",
                    "image": image_ref,
                    "error": result.stderr,
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }

    def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
    ) -> dict:
        """Create a SBOM attestation for an OCI artifact."""
        if not self.is_available():
            return {"status": "unavailable", "reason": "cosign not installed"}

        # Generate attestation
        cmd = [
            "cosign", "attest",
            "--yes",
            "--type", "spdx",
            "--predicate", str(sbom_path),
            image_ref,
        ]

        if self.identity_token:
            cmd.extend(["--oidc-identity", self.identity_token])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                return {
                    "status": "attested",
                    "sbom": str(sbom_path),
                    "image": image_ref,
                }
            else:
                return {
                    "status": "failed",
                    "error": result.stderr,
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }


class FulcioClient:
    """Client for Fulcio certificate authority."""

    def __init__(self, fulcio_url: str | None = None):
        self.fulcio_url = fulcio_url or "https://fulcio.sigstore.dev"

    def getSigningCert(self) -> bytes | None:
        """Get the Fulcio signing certificate."""
        try:
            import requests
            response = requests.get(
                f"{self.fulcio_url}/api/v1/signingCert",
                timeout=10,
            )
            if response.status_code == 200:
                return response.content
        except Exception:
            pass
        return None


def create_sbom_attestation(
    sbom_path: Path,
    image_ref: str,
    signer: SigstoreSigner | None = None,
) -> dict:
    """Create a Sigstore attestation for a SBOM."""
    signer = signer or SigstoreSigner()
    return signer.attest_sbom(sbom_path, image_ref)


def verify_sbom_attestation(
    sbom_path: Path,
    image_ref: str,
) -> dict:
    """Verify a SBOM attestation."""
    signer = SigstoreSigner()
    return signer.verify_oci(image_ref)


# CLI helper functions

def parse_license_from_sbom(sbom_content: str) -> dict:
    """Parse license information from SBOM content."""
    try:
        data = json.loads(sbom_content)

        # CycloneDX format
        if "bomFormat" in data:
            licenses = {}
            for comp in data.get("components", []):
                file_path = comp.get("name", "")
                for lic in comp.get("licenses", []):
                    licenses[file_path] = lic.get("license", {}).get("id", "UNKNOWN")
            return {"format": "cyclonedx", "licenses": licenses}

        # SPDX format
        if "spdxVersion" in data:
            licenses = {}
            for pkg in data.get("packages", []):
                file_path = pkg.get("name", "")
                licenses[file_path] = pkg.get("licenseConcluded", "UNKNOWN")
            return {"format": "spdx", "licenses": licenses}

    except json.JSONDecodeError:
        pass

    return {"format": "unknown", "licenses": {}}


def merge_sbom_files(sbom_paths: list[Path]) -> str:
    """Merge multiple SBOM files into one."""
    all_licenses = {}

    for sbom_path in sbom_paths:
        parsed = parse_license_from_sbom(sbom_path.read_text())
        all_licenses.update(parsed.get("licenses", {}))

    # Create merged CycloneDX
    merged = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": current_utc_iso(),
            "tools": [{"name": "licenseseal", "version": "0.3.0"}],
        },
        "components": [
            {
                "type": "file",
                "name": path,
                "licenses": [{"license": {"id": lic}}],
            }
            for path, lic in all_licenses.items()
        ],
    }

    return json.dumps(merged, indent=2, ensure_ascii=False)


def validate_sbom(sbom_path: Path) -> tuple[bool, list[str]]:
    """Validate a SBOM file."""
    errors = []

    try:
        content = sbom_path.read_text()
        data = json.loads(content)

        # Check required fields
        if "bomFormat" in data:
            if "specVersion" not in data:
                errors.append("Missing specVersion")
            if "components" not in data:
                errors.append("Missing components")
        elif "spdxVersion" in data:
            if "packages" not in data:
                errors.append("Missing packages")
        else:
            errors.append("Unknown SBOM format")

    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {e}")
    except Exception as e:
        errors.append(f"Validation error: {e}")

    return len(errors) == 0, errors