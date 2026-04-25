"""
LicenseSeal Language Server Protocol (LSP) Implementation
=========================================================
Provides real-time license boundary validation in IDEs.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Try to import pygls, fallback to basic implementation
try:
    from pygls.server import LanguageServer
    from pygls.protocol import JsonRPCMessageProtocol
    from pygls.types import (
        Diagnostic,
        DiagnosticSeverity,
        Position,
        Range,
        TextDocumentPositionParams,
        CodeAction,
        CodeActionKind,
        CodeActionParams,
        TextEdit,
        WorkspaceEdit,
    )
    from pygls.workspace import Document
    HAS_PYGLS = True
except ImportError:
    HAS_PYGLS = False
    # Basic fallback types
    class Diagnostic:
        def __init__(self, range, message, severity=None):
            self.range = range
            self.message = message
            self.severity = severity

    class LanguageServer:
        pass

    class Document:
        def __init__(self, uri, source=None):
            self.uri = uri
            self.source = source or ""

    class CodeActionKind:
        QuickFix = "quickfix"

    class TextEdit:
        def __init__(self, range=None, new_text=""):
            self.range = range
            self.new_text = new_text

    class WorkspaceEdit:
        def __init__(self, changes=None):
            self.changes = changes or {}

    class CodeAction:
        def __init__(self, title="", kind=None, diagnostics=None, edit=None):
            self.title = title
            self.kind = kind
            self.diagnostics = diagnostics or []
            self.edit = edit

    class CodeActionParams:
        pass

from .core import (
    BOUNDARY_BEGIN,
    BOUNDARY_END,
    has_existing_marker,
    parse_marker_fields,
    strip_license_boundary,
    make_marker_lines,
    insertion_index,
    comment_prefix_for,
)


@dataclass
class LSPConfig:
    """Configuration for the LicenseSeal LSP server."""
    host: str = "127.0.0.1"
    port: int = 8766
    log_file: Path | None = None
    strict_mode: bool = False
    check_on_save: bool = True
    check_on_type: bool = False
    default_license: str = "MIT"
    default_owner: str = "UNKNOWN"
    default_project: str = ""


@dataclass
class LicenseCheckResult:
    """Result of a license boundary check."""
    file_path: str
    has_marker: bool
    is_valid: bool
    license_id: Optional[str] = None
    owner: Optional[str] = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class LicenseSealLanguageServer:
    """
    Language Server Protocol implementation for LicenseSeal.
    Provides real-time license boundary validation.
    """

    def __init__(self, config: LSPConfig | None = None):
        self.config = config or LSPConfig()
        self._diagnostics: dict[str, list[Diagnostic]] = {}
        self._workspace_root: Optional[Path] = None

    def _log(self, message: str) -> None:
        """Log a message to the configured log file or stderr."""
        if self.config.log_file:
            try:
                self.config.log_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.config.log_file, "a") as f:
                    f.write(f"[{os.popen('date /t').read().strip()}] {message}\n")
            except Exception:
                pass
        print(f"[LicenseSeal LSP] {message}", file=sys.stderr)

    def set_workspace_root(self, root: Path) -> None:
        """Set the workspace root for license checks."""
        self._workspace_root = root

    def load_workspace_settings(self) -> dict:
        """Load lightweight LicenseSeal settings from .vscode/settings.json."""
        settings: dict = {}
        if not self._workspace_root:
            return settings
        path = self._workspace_root / ".vscode" / "settings.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return settings
        settings["license_id"] = raw.get("licenseseal.license", raw.get("licenseseal.defaultLicense", self.config.default_license))
        settings["owner"] = raw.get("licenseseal.owner", raw.get("licenseseal.defaultOwner", self.config.default_owner))
        settings["project"] = raw.get("licenseseal.project", raw.get("licenseseal.defaultProject", self.config.default_project))
        return settings

    def quickfix_marker_text(self, file_path: Path, source: str = "") -> str:
        """Build a marker edit suitable for LSP WorkspaceEdit insertion."""
        comment = comment_prefix_for(file_path, include_configs=True) or "#"
        settings = self.load_workspace_settings()
        root = self._workspace_root or file_path.parent
        try:
            relative = str(file_path.relative_to(root)).replace(os.sep, "/")
        except ValueError:
            relative = file_path.name
        project = settings.get("project") or root.name
        marker = make_marker_lines(
            comment=comment,
            license_id=settings.get("license_id", self.config.default_license),
            owner=settings.get("owner", self.config.default_owner),
            project=project,
            relative_path=relative,
            text_without_marker=strip_license_boundary(source),
            root=root,
        )
        return "\n".join(marker) + "\n\n"

    def code_actions_for_file(self, file_path: Path, uri: str | None = None, diagnostics: list | None = None) -> list:
        """
        Return LSP quick fixes for missing or stale LicenseSeal markers.

        The method returns real pygls CodeAction objects when pygls is installed
        and plain serializable dictionaries in fallback/test mode.
        """
        uri = uri or file_path.as_uri()
        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception:
            source = ""

        relevant = diagnostics or self.get_diagnostics(file_path)
        needs_marker = any("No LicenseSeal marker found" in getattr(d, "message", str(d)) for d in relevant)
        missing_sig = any("Missing AI_SIGNATURE" in getattr(d, "message", str(d)) for d in relevant)
        if not needs_marker and not missing_sig:
            return []

        lines = source.splitlines()
        idx = insertion_index(lines, file_path.suffix)
        new_text = self.quickfix_marker_text(file_path, source)
        edit_range = Range(start=Position(line=idx, character=0), end=Position(line=idx, character=0))
        edit = TextEdit(range=edit_range, new_text=new_text)

        title = "LicenseSeal Marker injizieren" if needs_marker else "LicenseSeal Marker aktualisieren"
        try:
            return [CodeAction(
                title=title,
                kind=CodeActionKind.QuickFix,
                diagnostics=relevant,
                edit=WorkspaceEdit(changes={uri: [edit]}),
            )]
        except TypeError:
            return [{
                "title": title,
                "kind": "quickfix",
                "edit": {"changes": {uri: [{"range": edit_range, "newText": new_text}]}},
            }]

    def check_file(self, file_path: Path) -> LicenseCheckResult:
        """
        Check a single file for license boundary compliance.
        """
        result = LicenseCheckResult(
            file_path=str(file_path),
            has_marker=False,
            is_valid=True,
        )

        try:
            text = file_path.read_text(encoding="utf-8")
        except Exception as e:
            result.errors.append(f"Cannot read file: {e}")
            result.is_valid = False
            return result

        # Check for marker
        if BOUNDARY_BEGIN in text and BOUNDARY_END in text:
            result.has_marker = True
            fields = parse_marker_fields(text)

            result.license_id = fields.get("SPDX-License-Identifier")
            result.owner = fields.get("Copyright", "").replace("Copyright (c) ", "")

            # Validate required fields
            if not result.license_id:
                result.errors.append("Missing SPDX-License-Identifier")
                result.is_valid = False

            if not result.owner:
                result.warnings.append("Missing Copyright owner")

            # Check for AI_SIGNATURE
            if not fields.get("AI_SIGNATURE"):
                result.warnings.append("Missing AI_SIGNATURE (notarization recommended)")

        else:
            result.has_marker = False
            result.warnings.append("No LicenseSeal marker found")

        return result

    def check_workspace(self, root: Path) -> dict[str, LicenseCheckResult]:
        """
        Check all files in a workspace for license compliance.
        """
        from .core import iter_candidate_files, DEFAULT_EXCLUDE_DIRS

        results = {}
        exclude_dirs = DEFAULT_EXCLUDE_DIRS.copy()

        for path in iter_candidate_files(root, exclude_dirs, include_configs=False):
            results[str(path)] = self.check_file(path)

        return results

    def get_diagnostics(self, file_path: Path) -> list[Diagnostic]:
        """
        Get LSP diagnostics for a file.
        """
        result = self.check_file(file_path)
        diagnostics = []

        # Convert errors to diagnostics
        for error in result.errors:
            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=0, character=0),
                    end=Position(line=0, character=0),
                ),
                message=error,
                severity=DiagnosticSeverity.Error if result.is_valid else None,
            ))

        # Convert warnings to diagnostics
        for warning in result.warnings:
            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=0, character=0),
                    end=Position(line=0, character=0),
                ),
                message=warning,
                severity=DiagnosticSeverity.Warning,
            ))

        return diagnostics

    def validate_license_compatibility(
        self,
        source_license: str,
        target_license: str,
    ) -> tuple[bool, str]:
        """
        Check if a source license is compatible with a target license.
        Returns (is_compatible, reason).
        """
        # Copyleft licenses that require derivative works to use the same license
        copyleft_licenses = {
            "AGPL-3.0-or-later": "AGPL-3.0",
            "AGPL-3.0-only": "AGPL-3.0",
            "GPL-3.0-or-later": "GPL-3.0",
            "GPL-3.0-only": "GPL-3.0",
            "GPL-2.0-or-later": "GPL-2.0",
            "GPL-2.0-only": "GPL-2.0",
            "LGPL-3.0-or-later": "LGPL-3.0",
            "LGPL-3.0-only": "LGPL-3.0",
            "MPL-2.0": "MPL-2.0",
            "EUPL-1.2": "EUPL-1.2",
        }

        # Permissive licenses that allow integration
        permissive_licenses = {
            "MIT": "MIT",
            "Apache-2.0": "Apache-2.0",
            "BSD-3-Clause": "BSD-3-Clause",
            "BSD-2-Clause": "BSD-2-Clause",
            "ISC": "ISC",
            "Unlicense": "Unlicense",
        }

        # Normalize license identifiers
        source_norm = source_license.replace("-or-later", "").replace("-only", "")
        target_norm = target_license.replace("-or-later", "").replace("-only", "")

        # Check if source is copyleft
        source_base = copyleft_licenses.get(source_license)
        if source_base:
            # Copyleft code cannot be integrated into proprietary projects
            if target_license not in copyleft_licenses:
                return False, f"Copyleft license '{source_license}' cannot be integrated into '{target_license}' projects"

        # Check specific incompatibilities
        incompatibilities = {
            ("GPL-3.0", "AGPL-3.0"): "GPL-3.0 code is incompatible with AGPL-3.0 projects",
            ("AGPL-3.0", "GPL-3.0"): "AGPL-3.0 code is incompatible with GPL-3.0 projects",
            ("GPL-2.0", "GPL-3.0"): "GPL-2.0 code cannot be upgraded to GPL-3.0 without permission",
        }

        key = (source_norm, target_norm)
        if key in incompatibilities:
            return False, incompatibilities[key]

        return True, "Compatible"


def code_action(params) -> list:
    """
    pygls-compatible code action entrypoint.

    This function is intentionally small and delegates to LicenseSealLanguageServer
    so it remains testable without running a full JSON-RPC server.
    """
    server = LicenseSealLanguageServer()
    uri = getattr(getattr(params, "text_document", None), "uri", "")
    diagnostics = getattr(getattr(params, "context", None), "diagnostics", [])
    if uri.startswith("file://"):
        path = Path(uri[7:])
    else:
        path = Path(uri)
    return server.code_actions_for_file(path, uri=uri, diagnostics=diagnostics)

def create_lsp_server(config: LSPConfig | None = None) -> LicenseSealLanguageServer:
    """Factory function to create an LSP server instance."""
    return LicenseSealLanguageServer(config)


def run_lsp_server(config: LSPConfig | None = None) -> int:
    """
    Run the LicenseSeal LSP server.
    """
    if not HAS_PYGLS:
        print("ERROR: pygls is required for LSP server.", file=sys.stderr)
        print("Install with: pip install licenseseal[lsp]", file=sys.stderr)
        return 1

    server = LicenseSealLanguageServer(config)
    server._log("Starting LicenseSeal LSP server...")

    # This would be the main loop for the LSP server
    # In practice, this would use the pygls server infrastructure
    return 0


# VS Code Extension manifest generation
def generate_vscode_extension_manifest() -> dict:
    """Generate package.json for VS Code extension."""
    return {
        "name": "licenseseal",
        "displayName": "LicenseSeal",
        "description": "AI-readable license boundary validation for VS Code",
        "version": "0.3.0",
        "publisher": "licenseseal",
        "engines": {
            "vscode": "^1.75.0"
        },
        "categories": [
            "Linters",
            "Other"
        ],
        "activationEvents": [
            "onLanguage:*",
            "workspaceContains:**/.licenseseal/*"
        ],
        "main": "./out/extension",
        "contributes": {
            "languages": [
                {
                    "id": "licenseseal-marker",
                    "extensions": [".licenseseal"],
                    "aliases": ["LicenseSeal Marker"]
                }
            ],
            "diagnostics": {
                "**/*": {
                    "validator": "licenseseal"
                }
            },
            "configuration": {
                "title": "LicenseSeal",
                "properties": {
                    "licenseseal.strictMode": {
                        "type": "boolean",
                        "default": false,
                        "description": "Enable strict license validation"
                    },
                    "licenseseal.checkOnSave": {
                        "type": "boolean",
                        "default": true,
                        "description": "Check license on file save"
                    }
                }
            }
        }
    }


# JetBrains plugin configuration (Kotlin DSL)
def generate_jetbrains_plugin_xml() -> str:
    """Generate plugin.xml for JetBrains IDEs."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin>
    <id>com.licenseseal.plugin</id>
    <name>LicenseSeal</name>
    <version>0.3.0</version>
    <vendor>LicenseSeal</vendor>
    <description>AI-readable license boundary validation</description>
    <depends>com.intellij.modules.platform</depends>
    <extensions xmlns="com.intellij">
        <localInspection
            language="*"
            groupName="LicenseSeal"
            enabled="true"
            level="WARNING"
            implementationClass="com.licenseseal.plugin.LicenseSealInspection"/>
    </extensions>
</idea-plugin>"""

# ---------------------------------------------------------------------------
# Inbound Paste Protection
# ---------------------------------------------------------------------------

@dataclass
class PasteProtectionConfig:
    """Configuration for shift-left inbound paste/license contamination checks."""
    enabled: bool = True
    min_paste_chars: int = 400
    similarity_threshold: float = 0.88
    incompatible_licenses: tuple[str, ...] = ("AGPL-3.0", "GPL-3.0", "GPL-2.0", "SSPL-1.0")


@dataclass
class PasteDiagnostic:
    message: str
    severity: str = "warning"
    confidence: float = 0.0
    source: str = "licenseseal.inbound"
    details: dict = field(default_factory=dict)


def looks_like_large_paste(old_text: str, new_text: str, cfg: PasteProtectionConfig | None = None) -> bool:
    """Heuristic paste detection based on inserted character delta."""
    cfg = cfg or PasteProtectionConfig()
    return cfg.enabled and max(0, len(new_text) - len(old_text)) >= cfg.min_paste_chars


def _quick_license_markers(text: str) -> list[str]:
    markers = []
    lowered = text.lower()
    if "ai_license_boundary_begin" in lowered or "licenseseal" in lowered:
        markers.append("LicenseSeal boundary/provenance marker")
    for lic in ["agpl-3.0", "gpl-3.0", "gpl-2.0", "sspl-1.0", "apache-2.0", "mit"]:
        if lic in lowered:
            markers.append(lic.upper())
    return markers


def inbound_paste_check(
    inserted_text: str,
    project_license: str = "",
    known_components: list[dict] | None = None,
    cfg: PasteProtectionConfig | None = None,
) -> list[PasteDiagnostic]:
    """
    Check pasted code for foreign provenance markers or known incompatible
    component fingerprints. `known_components` can contain dictionaries with:
    {name, license, shingles: [str], threshold}.
    """
    cfg = cfg or PasteProtectionConfig()
    diagnostics: list[PasteDiagnostic] = []
    markers = _quick_license_markers(inserted_text)
    for marker in markers:
        if marker in cfg.incompatible_licenses or any(marker.startswith(x) for x in cfg.incompatible_licenses):
            diagnostics.append(PasteDiagnostic(
                message=f"Inserted code appears to reference incompatible license/provenance marker: {marker}.",
                severity="error",
                confidence=0.95,
                details={"marker": marker, "project_license": project_license},
            ))
        elif marker.startswith("LicenseSeal"):
            diagnostics.append(PasteDiagnostic(
                message="Inserted code contains a LicenseSeal provenance boundary. Verify ownership and license before committing.",
                severity="warning",
                confidence=0.9,
                details={"marker": marker},
            ))
    # Lightweight local shingle overlap for enterprise-provided blocklists.
    try:
        from .core import generic_text_shingles, cosine_similarity
        inserted_sig = generic_text_shingles(inserted_text)
        for comp in known_components or []:
            comp_sig = comp.get("shingles") or {}
            if isinstance(comp_sig, list):
                comp_sig = {x: 1 for x in comp_sig}
            sim = cosine_similarity(inserted_sig, comp_sig)
            threshold = float(comp.get("threshold", cfg.similarity_threshold))
            if sim >= threshold:
                lic = str(comp.get("license", "unknown"))
                severity = "error" if lic in cfg.incompatible_licenses else "warning"
                diagnostics.append(PasteDiagnostic(
                    message=f"Inserted code is {sim:.0%} structurally similar to known component {comp.get('name', 'unknown')} ({lic}).",
                    severity=severity,
                    confidence=round(sim, 4),
                    details={"component": comp, "project_license": project_license},
                ))
    except Exception:
        pass
    return diagnostics


def paste_diagnostics_to_lsp(diagnostics: list[PasteDiagnostic], start_line: int = 0, end_line: int = 0):
    """Convert paste diagnostics to pygls Diagnostic objects when pygls is available."""
    out = []
    for d in diagnostics:
        severity = DiagnosticSeverity.Error if getattr(DiagnosticSeverity, "Error", 1) and d.severity == "error" else DiagnosticSeverity.Warning
        out.append(Diagnostic(
            range=Range(start=Position(line=start_line, character=0), end=Position(line=end_line, character=0)),
            message=d.message,
            severity=severity,
        ))
    return out
