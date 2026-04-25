"""
LicenseSeal Binary Provenance
=============================

Source-to-binary provenance helpers for Go, C/C++/ELF-style builds and Java JARs.
The audit path is intentionally dependency-light: it can recover embedded JSON
by scanning bytes, and uses zipfile for JAR manifests. pyelftools can be added by
enterprises later for deep section parsing.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from .core import current_utc_iso, project_signature


BEGIN = b"LICENSESEAL_PROVENANCE_BEGIN"
END = b"LICENSESEAL_PROVENANCE_END"


@dataclass
class BinaryProvenance:
    project_name: str
    project_id: str
    content_digest: str
    signature: str
    created_at: str
    tool: str = "licenseseal"
    schema: str = "licenseseal.binary-provenance.v1"

    def to_dict(self) -> dict:
        return asdict(self)

    def encode(self) -> bytes:
        return BEGIN + b"\n" + json.dumps(self.to_dict(), sort_keys=True).encode("utf-8") + b"\n" + END


def create_binary_provenance(root: Path, project_name: str = "", project_id: str = "") -> BinaryProvenance:
    sig = project_signature(root)
    digest = hashlib.sha256(json.dumps(sig, sort_keys=True).encode("utf-8")).hexdigest()
    pid = project_id or hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    signature = hashlib.sha256(f"{pid}:{digest}".encode("utf-8")).hexdigest()
    return BinaryProvenance(project_name or root.name, pid, digest, signature, current_utc_iso())


def go_ldflags(provenance: BinaryProvenance, variable: str = "main.LicenseSealProvenance") -> str:
    value = json.dumps(provenance.to_dict(), separators=(",", ":")).replace('"', '\\"')
    return f'-ldflags "-X {variable}={value}"'


def c_section_source(provenance: BinaryProvenance, symbol: str = "licenseseal_provenance") -> str:
    payload = provenance.encode().decode("utf-8").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return (
        '#include <stddef.h>\n'
        f'__attribute__((used, section(".note.licenseseal")))\n'
        f'const char {symbol}[] = "{payload}";\n'
    )


def write_c_section_file(path: Path, provenance: BinaryProvenance) -> Path:
    path.write_text(c_section_source(provenance), encoding="utf-8")
    return path


def inject_jar_manifest(jar_path: Path, provenance: BinaryProvenance, output: Path | None = None) -> Path:
    output = output or jar_path
    manifest_payload = "\n".join([
        "Manifest-Version: 1.0",
        f"LicenseSeal-Project-Id: {provenance.project_id}",
        f"LicenseSeal-Content-Digest: {provenance.content_digest}",
        f"LicenseSeal-Signature: {provenance.signature}",
        f"LicenseSeal-Created-At: {provenance.created_at}",
        "",
    ])
    tmp = output.with_suffix(output.suffix + ".tmp")
    with zipfile.ZipFile(jar_path, "r") as zin, zipfile.ZipFile(tmp, "w") as zout:
        names = set()
        for item in zin.infolist():
            if item.filename.upper() == "META-INF/MANIFEST.MF":
                continue
            names.add(item.filename)
            zout.writestr(item, zin.read(item.filename))
        zout.writestr("META-INF/MANIFEST.MF", manifest_payload)
    tmp.replace(output)
    return output


def extract_provenance_from_bytes(data: bytes) -> dict | None:
    start = data.find(BEGIN)
    if start == -1:
        return None
    start = data.find(b"\n", start)
    end = data.find(END, start)
    if start == -1 or end == -1:
        return None
    raw = data[start:end].strip()
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def audit_binary(path: Path) -> dict:
    if path.suffix.lower() == ".jar":
        try:
            with zipfile.ZipFile(path, "r") as z:
                manifest = z.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
            fields = {}
            for line in manifest.splitlines():
                if line.startswith("LicenseSeal-"):
                    k, _, v = line.partition(":")
                    fields[k.strip()] = v.strip()
            if fields:
                return {"path": str(path), "found": True, "format": "jar-manifest", "provenance": fields}
        except Exception:
            pass
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"path": str(path), "found": False, "error": str(exc)}
    payload = extract_provenance_from_bytes(data)
    return {"path": str(path), "found": payload is not None, "format": "byte-scan", "provenance": payload or {}}


def append_provenance_blob(binary_path: Path, provenance: BinaryProvenance, output: Path | None = None) -> Path:
    output = output or binary_path
    data = binary_path.read_bytes()
    output.write_bytes(data + b"\n" + provenance.encode() + b"\n")
    return output
