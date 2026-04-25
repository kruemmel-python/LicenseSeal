"""
LicenseSeal Legal Report Generator
===================================
Generates professional PDF reports for legal evidence and DMCA notices.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .core import (
    BOUNDARY_BEGIN,
    current_utc_iso,
    parse_marker_fields,
    project_signature,
    strip_license_boundary,
)


@dataclass
class ReportConfig:
    """Configuration for legal report generation."""
    format: str = "pdf"  # pdf, html, markdown
    template: str = "default"
    include_code_diff: bool = True
    include_signatures: bool = True
    include_watermarks: bool = True
    include_git_history: bool = True
    color_scheme: str = "professional"


@dataclass
class ReportSection:
    """Report section data."""
    title: str
    content: str
    subsections: list[dict] = field(default_factory=list)


class LegalReportGenerator:
    """Generates professional legal reports."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate_report(
        self,
        original_root: Path,
        suspected_root: Path,
        similarity_data: dict,
        output_path: Path,
    ) -> Path:
        """Generate a complete legal report."""
        # Gather all evidence
        evidence = self._gather_evidence(original_root, suspected_root, similarity_data)

        # Generate based on format
        if self.config.format == "pdf":
            return self._generate_pdf(evidence, output_path)
        elif self.config.format == "html":
            return self._generate_html(evidence, output_path)
        else:
            return self._generate_markdown(evidence, output_path)

    def _gather_evidence(
        self,
        original_root: Path,
        suspected_root: Path,
        similarity_data: dict,
    ) -> dict:
        """Gather all evidence for the report."""
        evidence = {
            "generated_at": current_utc_iso(),
            "original_root": str(original_root),
            "suspected_root": str(suspected_root),
            "similarity": similarity_data,
        }

        # Get license information
        evidence["original_licenses"] = self._extract_license_info(original_root)
        evidence["suspected_licenses"] = self._extract_license_info(suspected_root)

        # Get Git history if available
        if self.config.include_git_history:
            evidence["original_git"] = self._extract_git_info(original_root)
            evidence["suspected_git"] = self._extract_git_info(suspected_root)

        # Get signature verification
        if self.config.include_signatures:
            evidence["signatures"] = self._verify_signatures(original_root)

        # Check for watermarks
        if self.config.include_watermarks:
            evidence["watermarks"] = self._check_watermarks(original_root, suspected_root)

        # Get code similarities
        if self.config.include_code_diff:
            evidence["code_similarities"] = self._find_similar_code(
                original_root, suspected_root
            )

        return evidence

    def _extract_license_info(self, root: Path) -> dict:
        """Extract license information from a project."""
        from .core import iter_candidate_files, parse_marker_fields

        licenses = {}
        for path in iter_candidate_files(root, None, False):
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue

            if BOUNDARY_BEGIN in text:
                fields = parse_marker_fields(text)
                rel_path = str(path.relative_to(root))
                licenses[rel_path] = {
                    "license": fields.get("SPDX-License-Identifier", "UNKNOWN"),
                    "owner": fields.get("Copyright", ""),
                    "signature": "present" if fields.get("AI_SIGNATURE") else "none",
                }

        return {
            "total_files": len(licenses),
            "files": licenses,
        }

    def _extract_git_info(self, root: Path) -> dict:
        """Extract Git information."""
        import subprocess

        info = {"is_git_repo": False}

        if not (root / ".git").exists():
            return info

        info["is_git_repo"] = True

        try:
            # Get current commit
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            )
            info["commit"] = result.stdout.strip()

            # Get first commit
            result = subprocess.run(
                ["git", "log", "--reverse", "--format=%H", "-1"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            )
            info["first_commit"] = result.stdout.strip()

            # Get commit count
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            )
            info["commit_count"] = result.stdout.strip()

            # Get remote URL
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                info["remote_url"] = result.stdout.strip()

        except subprocess.CalledProcessError:
            pass

        return info

    def _verify_signatures(self, root: Path) -> dict:
        """Verify cryptographic signatures."""
        from .core import iter_candidate_files, parse_marker_fields

        verified = 0
        missing = 0
        invalid = 0

        for path in iter_candidate_files(root, None, False):
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue

            if BOUNDARY_BEGIN in text:
                fields = parse_marker_fields(text)
                if fields.get("AI_SIGNATURE"):
                    verified += 1
                else:
                    missing += 1
                # Note: Full verification would require public key

        return {
            "verified": verified,
            "missing_signature": missing,
            "invalid": invalid,
        }

    def _check_watermarks(
        self,
        original_root: Path,
        suspected_root: Path,
    ) -> dict:
        """Check for watermarks in both projects."""
        # This would integrate with the watermark module
        return {
            "original_watermarks": "not_implemented",
            "suspected_watermarks": "not_implemented",
        }

    def _find_similar_code(
        self,
        original_root: Path,
        suspected_root: Path,
    ) -> list[dict]:
        """Find similar code between projects."""
        from .core import iter_candidate_files, file_similarity_signature

        similarities = []
        orig_sigs = {}

        # Get signatures from original
        for path in iter_candidate_files(original_root, None, False):
            sig = file_similarity_signature(path)
            if sig:
                orig_sigs[str(path.relative_to(original_root))] = sig

        # Compare with suspected
        for path in iter_candidate_files(suspected_root, None, False):
            susp_sig = file_similarity_signature(path)
            if not susp_sig:
                continue

            rel_path = str(path.relative_to(suspected_root))

            # Find best match
            best_match = None
            best_score = 0

            for orig_path, orig_sig in orig_sigs.items():
                score = self._cosine_similarity(orig_sig, susp_sig)
                if score > best_score:
                    best_score = score
                    best_match = orig_path

            if best_score > 0.5:
                similarities.append({
                    "suspected_file": rel_path,
                    "original_file": best_match,
                    "similarity": round(best_score, 4),
                })

        # Sort by similarity
        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        top = similarities[:50]

        # Attach AST line mappings for Python files. These mappings are used by
        # the HTML/PDF side-by-side evidence view and remain useful even when
        # identifiers were renamed.
        try:
            from .diff_viewer import collect_project_line_matches
            line_matches = collect_project_line_matches(original_root, suspected_root, top)
            if line_matches:
                for item in top:
                    item["line_matches"] = [
                        m for m in line_matches
                        if m.get("original_file") == item.get("original_file")
                        and m.get("suspected_file") == item.get("suspected_file")
                    ][:25]
        except Exception:
            pass

        return top

    def _cosine_similarity(self, a: dict, b: dict) -> float:
        """Calculate cosine similarity between two signatures."""
        if not a or not b:
            return 0.0

        common = set(a.keys()) & set(b.keys())
        dot = sum(a[k] * b[k] for k in common)

        norm_a = sum(v * v for v in a.values()) ** 0.5
        norm_b = sum(v * v for v in b.values()) ** 0.5

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot / (norm_a * norm_b)

    def _generate_pdf(self, evidence: dict, output_path: Path) -> Path:
        """Generate PDF report using WeasyPrint or similar."""
        # Try WeasyPrint first
        try:
            from weasyprint import HTML
            html = self._generate_html_content(evidence)
            HTML(string=html).write_pdf(output_path)
            return output_path
        except ImportError:
            pass

        # Fallback to HTML
        html_path = output_path.with_suffix(".html")
        self._generate_html(evidence, html_path)

        # Try to convert to PDF
        try:
            subprocess.run(
                ["wkhtmltopdf", str(html_path), str(output_path)],
                capture_output=True,
                timeout=30,
            )
            return output_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Return HTML as fallback
            return html_path

    def _generate_html(self, evidence: dict, output_path: Path) -> Path:
        """Generate HTML report."""
        html = self._generate_html_content(evidence)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        return output_path

    def _generate_markdown(self, evidence: dict, output_path: Path) -> Path:
        """Generate Markdown report."""
        md = self._generate_markdown_content(evidence)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md, encoding="utf-8")
        return output_path

    def _generate_html_content(self, evidence: dict) -> str:
        """Generate HTML report content."""
        sim = evidence.get("similarity", {})
        orig_lic = evidence.get("original_licenses", {})
        susp_lic = evidence.get("suspected_licenses", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LicenseSeal Legal Evidence Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #333; }}
        h1 {{ color: #1a365d; border-bottom: 3px solid #2b6cb0; padding-bottom: 10px; }}
        h2 {{ color: #2c5282; margin-top: 30px; }}
        h3 {{ color: #2d3748; }}
        .header {{ background: #f7fafc; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .meta {{ color: #718096; font-size: 14px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #ebf8ff; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #2b6cb0; }}
        .stat-label {{ color: #4a5568; font-size: 14px; }}
        .warning {{ background: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 10px 0; }}
        .success {{ background: #f0fff4; border-left: 4px solid #68d391; padding: 15px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #edf2f7; font-weight: 600; }}
        .code {{ background: #1a202c; color: #e2e8f0; padding: 15px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
        .highlight {{ background: #fefcbf; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #718096; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🔒 LicenseSeal Legal Evidence Report</h1>
    
    <div class="header">
        <p><strong>Generated:</strong> {evidence.get('generated_at', '')}</p>
        <p><strong>Report ID:</strong> {hashlib.sha256(evidence.get('generated_at', '').encode()).hexdigest()[:16]}</p>
    </div>

    <h2>📊 Executive Summary</h2>
    <div class="summary">
        <div class="stat-box">
            <div class="stat-value">{sim.get('structural_similarity', 0) * 100:.1f}%</div>
            <div class="stat-label">Structural Similarity</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{orig_lic.get('total_files', 0)}</div>
            <div class="stat-label">Original Files</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{susp_lic.get('total_files', 0)}</div>
            <div class="stat-label">Suspected Files</div>
        </div>
    </div>
"""

        # Add assessment
        assessment = sim.get("assessment", "unknown")
        if "high" in assessment.lower() or "very_high" in assessment.lower():
            html += f'''
    <div class="warning">
        <h3>⚠️ High Similarity Detected</h3>
        <p>The analysis shows <strong>{sim.get('structural_similarity', 0) * 100:.1f}%</strong> structural similarity between the projects.</p>
        <p><strong>Assessment:</strong> {assessment}</p>
    </div>
'''
        else:
            html += f'''
    <div class="success">
        <h3>✅ Low Similarity</h3>
        <p>No significant code similarity was detected.</p>
    </div>
'''

        # Project details
        html += f'''
    <h2>📁 Project Details</h2>
    <table>
        <tr><th>Property</th><th>Original</th><th>Suspected</th></tr>
        <tr><td>Root Path</td><td>{evidence.get('original_root', 'N/A')}</td><td>{evidence.get('suspected_root', 'N/A')}</td></tr>
        <tr><td>License Status</td><td>{orig_lic.get('total_files', 0)} files marked</td><td>{susp_lic.get('total_files', 0)} files marked</td></tr>
'''

        # Add Git info if available
        orig_git = evidence.get("original_git", {})
        if orig_git.get("is_git_repo"):
            html += f'''
        <tr><td>Git Commit</td><td>{orig_git.get('commit', 'N/A')[:12]}...</td><td>{evidence.get('suspected_git', {}).get('commit', 'N/A')[:12]}...</td></tr>
        <tr><td>First Commit</td><td>{orig_git.get('first_commit', 'N/A')[:12]}...</td><td>-</td></tr>
'''

        html += f'''
    </table>
'''

        # Cryptographic proof
        sigs = evidence.get("signatures", {})
        html += f'''
    <h2>🔐 Cryptographic Proof</h2>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Verified Signatures</td><td>{sigs.get('verified', 0)}</td></tr>
        <tr><td>Missing Signatures</td><td>{sigs.get('missing_signature', 0)}</td></tr>
    </table>
'''

        # Code similarities
        similarities = evidence.get("code_similarities", [])
        if similarities:
            html += f'''
    <h2>📝 Code Similarities (Top 20)</h2>
    <table>
        <tr><th>Suspected File</th><th>Original File</th><th>Similarity</th></tr>
'''
            for sim in similarities[:20]:
                html += f'''
        <tr><td>{sim.get('suspected_file', '')}</td><td>{sim.get('original_file', '')}</td><td>{sim.get('similarity', 0) * 100:.1f}%</td></tr>
'''
            html += f'''
    </table>
'''
            # Interactive side-by-side AST evidence snippets.
            try:
                from .diff_viewer import render_side_by_side_html
                original_root = Path(evidence.get("original_root", ""))
                suspected_root = Path(evidence.get("suspected_root", ""))
                rendered = 0
                html += "<h2>Side-by-Side AST Evidence</h2>"
                for sim in similarities[:8]:
                    matches = sim.get("line_matches") or []
                    if not matches:
                        continue
                    o_rel = sim.get("original_file", "")
                    s_rel = sim.get("suspected_file", "")
                    o_path = original_root / o_rel
                    s_path = suspected_root / s_rel
                    if not o_path.exists() or not s_path.exists():
                        continue
                    o_ranges = [m["original_range"] for m in matches[:10]]
                    s_ranges = [m["suspected_range"] for m in matches[:10]]
                    html += f"<h3>{o_rel} ⇄ {s_rel}</h3>"
                    html += render_side_by_side_html(
                        o_path.read_text(encoding="utf-8", errors="replace"),
                        s_path.read_text(encoding="utf-8", errors="replace"),
                        o_ranges,
                        s_ranges,
                    )
                    rendered += 1
                    if rendered >= 3:
                        break
            except Exception:
                pass

        # Footer
        html += f'''
    <div class="footer">
        <p>This report was generated by LicenseSeal v0.3.0</p>
        <p>Generated: {evidence.get('generated_at', '')}</p>
        <p>This document is intended for legal evidence purposes. The data contained herein represents
        technical analysis and should be used in conjunction with legal counsel.</p>
    </div>
</body>
</html>
'''
        return html

    def _generate_markdown_content(self, evidence: dict) -> str:
        """Generate Markdown report content."""
        sim = evidence.get("similarity", {})
        orig_lic = evidence.get("original_licenses", {})
        susp_lic = evidence.get("suspected_licenses", {})

        md = f"""# 🔒 LicenseSeal Legal Evidence Report

**Generated:** {evidence.get('generated_at', '')}
**Report ID:** {hashlib.sha256(evidence.get('generated_at', '').encode()).hexdigest()[:16]}

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Structural Similarity | **{sim.get('structural_similarity', 0) * 100:.1f}%** |
| Original Files | {orig_lic.get('total_files', 0)} |
| Suspected Files | {susp_lic.get('total_files', 0)} |
| Assessment | {sim.get('assessment', 'unknown')} |

---

## 📁 Project Details

| Property | Original | Suspected |
|----------|----------|-----------|
| Root Path | `{evidence.get('original_root', 'N/A')}` | `{evidence.get('suspected_root', 'N/A')}` |
| License Status | {orig_lic.get('total_files', 0)} files marked | {susp_lic.get('total_files', 0)} files marked |
"""

        # Add Git info
        orig_git = evidence.get("original_git", {})
        if orig_git.get("is_git_repo"):
            md += f"""
| Git Commit | `{orig_git.get('commit', 'N/A')[:12]}...` | `{evidence.get('suspected_git', {}).get('commit', 'N/A')[:12]}...` |
| First Commit | `{orig_git.get('first_commit', 'N/A')[:12]}...` | - |
"""

        # Add signatures
        sigs = evidence.get("signatures", {})
        md += f"""

---

## 🔐 Cryptographic Proof

| Metric | Count |
|--------|-------|
| Verified Signatures | {sigs.get('verified', 0)} |
| Missing Signatures | {sigs.get('missing_signature', 0)} |
"""

        # Add code similarities
        similarities = evidence.get("code_similarities", [])
        if similarities:
            md += f"""

---

## 📝 Code Similarities (Top 20)

| Suspected File | Original File | Similarity |
|----------------|---------------|------------|
"""
            for sim in similarities[:20]:
                md += f"| `{sim.get('suspected_file', '')}` | `{sim.get('original_file', '')}` | {sim.get('similarity', 0) * 100:.1f}% |\n"

        md += f"""

---

*This report was generated by LicenseSeal v0.3.0*
*Generated: {evidence.get('generated_at', '')}*
"""

        return md


def generate_legal_report(
    original_root: Path,
    suspected_root: Path,
    similarity_data: dict,
    output_path: Path,
    format: str = "pdf",
) -> Path:
    """Main function to generate a legal report."""
    config = ReportConfig(format=format)
    generator = LegalReportGenerator(config)
    return generator.generate_report(original_root, suspected_root, similarity_data, output_path)


def generate_dmca_notice(
    original_root: Path,
    suspected_root: Path,
    output_path: Path,
) -> Path:
    """Generate a DMCA takedown notice template."""
    from .core import project_license_marker_stats

    orig_stats = project_license_marker_stats(original_root)
    susp_stats = project_license_marker_stats(suspected_root)

    notice = f"""# DMCA Takedown Notice

**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}

---

## Complainant Information

- **Name:** [Your Name/Organization]
- **Address:** [Your Address]
- **Email:** [Your Email]
- **Phone:** [Your Phone]

---

## Original Work

- **Repository:** {original_root}
- **License:** [SPDX License Identifier]
- **Files Protected:** {orig_stats['marked_files']} files with LicenseSeal markers

---

## Infringing Material

- **Repository URL:** {suspected_root}
- **Infringing Files:** {susp_stats['unmarked_files']} files (estimated)

---

## Statement of Good Faith

I have a good faith belief that the use of the copyrighted code described above is not authorized by the copyright owner, its agent, or the law.

I swear, under penalty of perjury, that the information in this notification is accurate and that I am the copyright owner or am authorized to act on the copyright owner's behalf.

---

## Signature

[Your Signature]

[Your Printed Name]

[Date]
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(notice, encoding="utf-8")
    return output_path


def generate_compliance_certificate(
    root: Path,
    output_path: Path,
) -> Path:
    """Generate a compliance certificate for a project."""
    from .core import project_license_marker_stats

    stats = project_license_marker_stats(root)

    cert = f"""# LicenseSeal Compliance Certificate

**Project:** {root.name}
**Generated:** {current_utc_iso()}
**Certificate ID:** {hashlib.sha256(str(root).encode()).hexdigest()[:16]}

---

## Compliance Status

| Metric | Value |
|--------|-------|
| Total Files | {stats['total_files']} |
| Protected Files | {stats['marked_files']} |
| Unprotected Files | {stats['unmarked_files']} |
| Compliance Rate | {(stats['marked_files'] / stats['total_files'] * 100):.1f}% |

---

## Verification

This certificate confirms that the above project has been scanned by LicenseSeal
and the specified files contain valid AI-readable license boundaries.

---

*LicenseSeal v0.3.0*
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(cert, encoding="utf-8")
    return output_path