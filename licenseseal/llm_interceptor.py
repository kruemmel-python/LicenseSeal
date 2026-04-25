"""
LicenseSeal LLM prompt/context interceptor
==========================================
A defensive HTTP proxy/scanner for local LLM workflows. It can sit in front of
Ollama, LM Studio, or OpenAI-compatible endpoints and scan prompt/response text
for LicenseSeal markers, honey logic, and copyleft contamination indicators.
"""
from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .core import BOUNDARY_BEGIN, BOUNDARY_END
from .watermark import extract_watermark, extract_honey_logic_fingerprints
try:
    from .honey_multilang import MultiLanguageHoneyLogicDetector
except Exception:  # pragma: no cover
    MultiLanguageHoneyLogicDetector = None  # type: ignore


COPYLEFT_LICENSE_RE = re.compile(r"\b(AGPL-?3\.0|GPL-?3\.0|GPL-?2\.0|LGPL|SSPL|EUPL)\b", re.I)


@dataclass
class InterceptorPolicy:
    block_on_marker: bool = True
    block_on_honey_logic: bool = True
    warn_on_copyleft: bool = True
    max_body_bytes: int = 2_000_000


@dataclass
class InterceptorFinding:
    kind: str
    severity: str
    message: str
    confidence: float = 1.0
    details: dict = field(default_factory=dict)


@dataclass
class InterceptorResult:
    allowed: bool
    findings: list[InterceptorFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "findings": [f.__dict__ for f in self.findings],
        }


def extract_texts(payload: Any) -> list[str]:
    texts: list[str] = []
    if isinstance(payload, str):
        texts.append(payload)
    elif isinstance(payload, dict):
        for key, value in payload.items():
            if key in {"prompt", "response", "content", "text", "message"} and isinstance(value, str):
                texts.append(value)
            else:
                texts.extend(extract_texts(value))
    elif isinstance(payload, list):
        for item in payload:
            texts.extend(extract_texts(item))
    return texts


def scan_text(text: str, policy: InterceptorPolicy | None = None) -> InterceptorResult:
    policy = policy or InterceptorPolicy()
    findings: list[InterceptorFinding] = []

    if BOUNDARY_BEGIN in text or BOUNDARY_END in text:
        findings.append(InterceptorFinding(
            kind="licenseseal_boundary",
            severity="error" if policy.block_on_marker else "warning",
            message="LicenseSeal boundary marker detected in LLM context.",
            confidence=0.99,
        ))

    try:
        wm = extract_watermark(text)
        if wm:
            findings.append(InterceptorFinding(
                kind="watermark",
                severity="error" if policy.block_on_marker else "warning",
                message="LicenseSeal zero-width watermark detected in LLM context.",
                confidence=0.92,
                details={"watermark": wm[:128]},
            ))
    except Exception:
        pass

    try:
        fps = extract_honey_logic_fingerprints(text)
        if fps:
            findings.append(InterceptorFinding(
                kind="honey_logic_python",
                severity="error" if policy.block_on_honey_logic else "warning",
                message="Python honey-logic sentinel detected in LLM context.",
                confidence=0.95,
                details={"count": len(fps)},
            ))
    except Exception:
        pass

    if MultiLanguageHoneyLogicDetector is not None:
        try:
            detector = MultiLanguageHoneyLogicDetector()
            fps = detector.extract(text, language="auto") if hasattr(detector, "extract") else []
            if fps:
                findings.append(InterceptorFinding(
                    kind="honey_logic_multilang",
                    severity="error" if policy.block_on_honey_logic else "warning",
                    message="Multi-language honey-logic sentinel detected in LLM context.",
                    confidence=0.90,
                    details={"count": len(fps)},
                ))
        except Exception:
            pass

    m = COPYLEFT_LICENSE_RE.search(text)
    if m and policy.warn_on_copyleft:
        findings.append(InterceptorFinding(
            kind="copyleft_indicator",
            severity="warning",
            message=f"Copyleft license indicator detected: {m.group(1)}.",
            confidence=0.75,
        ))

    allowed = True
    for f in findings:
        if f.severity == "error":
            allowed = False
            break
    return InterceptorResult(allowed=allowed, findings=findings)


def scan_payload(payload: Any, policy: InterceptorPolicy | None = None) -> InterceptorResult:
    policy = policy or InterceptorPolicy()
    merged: list[InterceptorFinding] = []
    allowed = True
    for text in extract_texts(payload):
        res = scan_text(text, policy)
        merged.extend(res.findings)
        allowed = allowed and res.allowed
    return InterceptorResult(allowed=allowed, findings=merged)


class InterceptorProxyHandler(BaseHTTPRequestHandler):
    target_base = "http://localhost:11434"
    policy = InterceptorPolicy()

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        if length > self.policy.max_body_bytes:
            self._send_json(413, {"error": "request too large"})
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = body.decode("utf-8", "ignore")

        inbound = scan_payload(payload, self.policy)
        if not inbound.allowed:
            self._send_json(451, {"error": "LicenseSeal interceptor blocked prompt", "findings": inbound.to_dict()["findings"]})
            return

        req = urllib.request.Request(
            urljoin(self.target_base.rstrip("/") + "/", self.path.lstrip("/")),
            data=body,
            method="POST",
            headers={k: v for k, v in self.headers.items() if k.lower() not in {"host", "content-length"}},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                response_body = resp.read()
                content_type = resp.headers.get("Content-Type", "application/json")
                try:
                    response_payload = json.loads(response_body.decode("utf-8"))
                except Exception:
                    response_payload = response_body.decode("utf-8", "ignore")
                outbound = scan_payload(response_payload, self.policy)
                if not outbound.allowed:
                    self._send_json(451, {"error": "LicenseSeal interceptor blocked response", "findings": outbound.to_dict()["findings"]})
                    return
                self.send_response(resp.status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)
        except urllib.error.HTTPError as exc:
            self._send_json(exc.code, {"error": exc.reason})
        except Exception as exc:
            self._send_json(502, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        return


def serve_proxy(host: str, port: int, target_base: str, policy: InterceptorPolicy | None = None) -> None:
    handler = type("LicenseSealInterceptorProxyHandler", (InterceptorProxyHandler,), {})
    handler.target_base = target_base
    handler.policy = policy or InterceptorPolicy()
    server = ThreadingHTTPServer((host, port), handler)
    server.serve_forever()
