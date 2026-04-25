"""
LicenseSeal SCA/license conflict checks
======================================
Lightweight manifest parsing and license compatibility checks before marker
injection. This is intentionally local-first: it does not call package registries
unless future integrations opt in.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


PERMISSIVE = {"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Zlib"}
WEAK_COPYLEFT = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"}
STRONG_COPYLEFT = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"}
PROPRIETARY = {"Proprietary", "UNLICENSED", "UNLICENSED/PROPRIETARY", "LicenseRef-Proprietary"}


@dataclass
class LicenseFinding:
    source: str
    license_id: str
    kind: str = "project"
    package: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class LicenseConflict:
    severity: str
    message: str
    finding: LicenseFinding | None = None


@dataclass
class SCAReport:
    root: str
    target_license: str
    findings: list[LicenseFinding] = field(default_factory=list)
    conflicts: list[LicenseConflict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(c.severity == "error" for c in self.conflicts)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "target_license": self.target_license,
            "ok": self.ok,
            "findings": [f.__dict__ for f in self.findings],
            "conflicts": [
                {"severity": c.severity, "message": c.message, "finding": c.finding.__dict__ if c.finding else None}
                for c in self.conflicts
            ],
        }


def normalize_license(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip().strip('"').strip("'")
    value = value.replace("GPL-3.0-or-later", "GPL-3.0").replace("AGPL-3.0-or-later", "AGPL-3.0")
    value = value.replace("GPLv3", "GPL-3.0").replace("AGPLv3", "AGPL-3.0")
    return value


def _parse_pyproject(path: Path) -> list[LicenseFinding]:
    try:
        import tomllib
    except Exception:  # pragma: no cover
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    project = data.get("project", {})
    lic = project.get("license", "")
    if isinstance(lic, dict):
        lic = lic.get("text") or lic.get("file") or ""
    findings = []
    if lic:
        findings.append(LicenseFinding(str(path), normalize_license(str(lic)), "project"))
    tool = data.get("tool", {}).get("poetry", {})
    if tool.get("license"):
        findings.append(LicenseFinding(str(path), normalize_license(str(tool["license"])), "project"))
    return findings


def _parse_package_json(path: Path) -> list[LicenseFinding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    findings = []
    lic = data.get("license")
    if lic:
        findings.append(LicenseFinding(str(path), normalize_license(str(lic)), "project", data.get("name", "")))
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        for name in (data.get(key) or {}):
            # package.json generally lacks dependency license locally; record package for later enrichment.
            findings.append(LicenseFinding(str(path), "", "dependency", name, {"manifest_section": key}))
    return findings


def _parse_cargo(path: Path) -> list[LicenseFinding]:
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkg = data.get("package", {})
    lic = pkg.get("license", "")
    return [LicenseFinding(str(path), normalize_license(str(lic)), "project", pkg.get("name", ""))] if lic else []


def _parse_go_mod(path: Path) -> list[LicenseFinding]:
    findings = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return findings
    module = ""
    m = re.search(r"^\s*module\s+(\S+)", text, re.M)
    if m:
        module = m.group(1)
    # go.mod has no canonical license field; keep project identity only.
    findings.append(LicenseFinding(str(path), "", "project", module, {"note": "go.mod has no license field"}))
    return findings


def _parse_pom(path: Path) -> list[LicenseFinding]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    def findall(expr: str):
        return root.findall(expr, ns) if ns else root.findall(expr.replace("m:", ""))
    findings = []
    for lic in findall(".//m:licenses/m:license" if ns else ".//licenses/license"):
        name = lic.findtext("m:name", default="", namespaces=ns) if ns else lic.findtext("name", default="")
        if name:
            findings.append(LicenseFinding(str(path), normalize_license(name), "project"))
    return findings


def _parse_requirements(path: Path) -> list[LicenseFinding]:
    findings = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return findings
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        pkg = re.split(r"[<>=~!;\[]", line, 1)[0].strip()
        if pkg:
            findings.append(LicenseFinding(str(path), "", "dependency", pkg))
    return findings


PARSERS = {
    "pyproject.toml": _parse_pyproject,
    "package.json": _parse_package_json,
    "Cargo.toml": _parse_cargo,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom,
    "requirements.txt": _parse_requirements,
}


def discover_manifests(root: Path) -> list[Path]:
    out: list[Path] = []
    skip = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
    for p in root.rglob("*"):
        if any(part in skip for part in p.parts):
            continue
        if p.is_file() and p.name in PARSERS:
            out.append(p)
    return out


def scan_manifests(root: Path) -> list[LicenseFinding]:
    findings: list[LicenseFinding] = []
    for path in discover_manifests(root):
        findings.extend(PARSERS[path.name](path))
    return findings


def license_family(license_id: str) -> str:
    lic = normalize_license(license_id)
    if not lic:
        return "unknown"
    if lic in PERMISSIVE:
        return "permissive"
    if lic in WEAK_COPYLEFT:
        return "weak_copyleft"
    if lic in STRONG_COPYLEFT:
        return "strong_copyleft"
    if lic in PROPRIETARY or lic.lower() in {"private", "closed-source"}:
        return "proprietary"
    if "AGPL" in lic or "GPL" in lic or "SSPL" in lic:
        return "strong_copyleft"
    if "MIT" in lic or "Apache" in lic or "BSD" in lic:
        return "permissive"
    return "unknown"


def check_compatibility(target_license: str, findings: list[LicenseFinding]) -> list[LicenseConflict]:
    target_family = license_family(target_license)
    conflicts: list[LicenseConflict] = []
    for f in findings:
        if not f.license_id:
            continue
        fam = license_family(f.license_id)
        if f.kind == "project":
            if fam == "proprietary" and target_family in {"strong_copyleft", "weak_copyleft"}:
                conflicts.append(LicenseConflict(
                    "error",
                    f"Injecting {target_license} conflicts with proprietary project declaration {f.license_id}.",
                    f,
                ))
            elif fam == "permissive" and target_family == "strong_copyleft":
                conflicts.append(LicenseConflict(
                    "warning",
                    f"Target license {target_license} is stronger than project manifest license {f.license_id}.",
                    f,
                ))
            elif fam == "strong_copyleft" and target_family in {"permissive", "proprietary"}:
                conflicts.append(LicenseConflict(
                    "error",
                    f"Project manifest declares {f.license_id}; target marker {target_license} may be incompatible.",
                    f,
                ))
        elif f.kind == "dependency":
            if fam == "strong_copyleft" and target_family in {"permissive", "proprietary"}:
                conflicts.append(LicenseConflict(
                    "warning",
                    f"Dependency {f.package} appears to use {f.license_id}; review copyleft obligations.",
                    f,
                ))
    return conflicts


def check_project(root: Path, target_license: str) -> SCAReport:
    findings = scan_manifests(root)
    conflicts = check_compatibility(target_license, findings)
    return SCAReport(str(root.resolve()), target_license, findings, conflicts)
