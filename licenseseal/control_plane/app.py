from __future__ import annotations

import json
import os
import uuid
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    HAS_FASTAPI = True
except Exception:  # pragma: no cover
    HAS_FASTAPI = False
    FastAPI = None  # type: ignore
    HTTPException = Exception  # type: ignore

from ..enterprise import EnterpriseRegistry, RegistryConfig


ROLES = {"admin", "legal", "developer", "viewer"}


@dataclass
class ControlPlaneConfig:
    database_url: str = os.environ.get("LICENSESEAL_DATABASE_URL", "postgresql://localhost:5432/licenseseal")
    api_keys: dict[str, str] = field(default_factory=dict)  # key -> role
    webhook_file: Path = Path(os.environ.get("LICENSESEAL_WEBHOOKS", ".licenseseal/webhooks.json"))

    @classmethod
    def from_env(cls) -> "ControlPlaneConfig":
        keys: dict[str, str] = {}
        raw = os.environ.get("LICENSESEAL_CONTROL_PLANE_KEYS", "")
        # format: key:role,key2:role
        for item in raw.split(","):
            if ":" in item:
                key, role = item.split(":", 1)
                keys[key.strip()] = role.strip()
        default = os.environ.get("LICENSESEAL_API_KEY")
        if default:
            keys.setdefault(default, "admin")
        if not keys:
            keys["dev-local"] = "admin"
        return cls(api_keys=keys)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def require_role(config: ControlPlaneConfig, *allowed: str):
    async def dep(x_licenseseal_api_key: str = Header(default="")) -> dict:
        role = config.api_keys.get(x_licenseseal_api_key)
        if not role:
            raise HTTPException(status_code=401, detail="missing or invalid API key")
        if allowed and role not in allowed and role != "admin":
            raise HTTPException(status_code=403, detail=f"role {role} not allowed")
        return {"role": role, "api_key": x_licenseseal_api_key}
    return dep


def _registry(config: ControlPlaneConfig) -> EnterpriseRegistry:
    return EnterpriseRegistry(RegistryConfig(database_url=config.database_url))


def _safe_db_call(fn, fallback):
    try:
        return fn()
    except Exception as exc:
        return {"warning": str(exc), "items": fallback}


def load_webhooks(config: ControlPlaneConfig) -> list[dict]:
    try:
        return json.loads(config.webhook_file.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_webhooks(config: ControlPlaneConfig, hooks: list[dict]) -> None:
    config.webhook_file.parent.mkdir(parents=True, exist_ok=True)
    config.webhook_file.write_text(json.dumps(hooks, indent=2), encoding="utf-8")


def emit_webhook(url: str, event: dict, timeout: int = 8) -> bool:
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def create_app(config: ControlPlaneConfig | None = None):
    if not HAS_FASTAPI:
        raise RuntimeError('FastAPI is required. Install with: pip install "licenseseal[control-plane]"')
    config = config or ControlPlaneConfig.from_env()
    app = FastAPI(title="LicenseSeal Enterprise Control Plane", version="1.0.0")

    @app.get("/health")
    async def health():
        return {"ok": True, "service": "licenseseal-control-plane", "time": _now()}

    @app.get("/", response_class=HTMLResponse)
    async def index(user=Depends(require_role(config, "admin", "legal", "developer", "viewer"))):
        return """
        <html><head><title>LicenseSeal Control Plane</title></head>
        <body>
          <h1>LicenseSeal Enterprise Control Plane</h1>
          <p>Use the JSON API for projects, scans, alerts and webhooks.</p>
          <ul>
            <li><code>/api/projects</code></li>
            <li><code>/api/scans</code></li>
            <li><code>/api/alerts</code></li>
            <li><code>/api/webhooks</code></li>
          </ul>
        </body></html>
        """

    @app.get("/api/me")
    async def me(user=Depends(require_role(config, "admin", "legal", "developer", "viewer"))):
        return user

    @app.get("/api/projects")
    async def projects(user=Depends(require_role(config, "admin", "legal", "developer", "viewer"))):
        reg = _registry(config)
        def call():
            conn = reg._get_connection()
            cur = conn.cursor()
            cur.execute("SELECT id,name,owner,license_id,status,indexed_at,last_scanned_at FROM registry_projects ORDER BY indexed_at DESC LIMIT 500")
            rows = cur.fetchall()
            return {"items": [
                {"id": str(r[0]), "name": r[1], "owner": r[2], "license_id": r[3], "status": r[4], "indexed_at": str(r[5]), "last_scanned_at": str(r[6])}
                for r in rows
            ]}
        return _safe_db_call(call, [])

    @app.get("/api/scans")
    async def scans(user=Depends(require_role(config, "admin", "legal", "developer", "viewer"))):
        reg = _registry(config)
        def call():
            conn = reg._get_connection()
            cur = conn.cursor()
            cur.execute("SELECT id,original_project_id,suspected_url,similarity_score,status,scanned_at FROM scan_results ORDER BY scanned_at DESC LIMIT 500")
            rows = cur.fetchall()
            return {"items": [
                {"id": str(r[0]), "project_id": str(r[1]), "suspected_url": r[2], "score": float(r[3] or 0), "status": r[4], "scanned_at": str(r[5])}
                for r in rows
            ]}
        return _safe_db_call(call, [])

    @app.get("/api/alerts")
    async def alerts(user=Depends(require_role(config, "admin", "legal", "viewer"))):
        scans_data = await scans(user)
        items = scans_data.get("items", []) if isinstance(scans_data, dict) else []
        high = [s for s in items if float(s.get("score", 0)) >= 0.85]
        return {"items": high, "threshold": 0.85}

    @app.get("/api/webhooks")
    async def webhooks(user=Depends(require_role(config, "admin", "legal"))):
        return {"items": load_webhooks(config)}

    @app.post("/api/webhooks")
    async def add_webhook(request: Request, user=Depends(require_role(config, "admin"))):
        payload = await request.json()
        url = payload.get("url")
        event = payload.get("event", "high_similarity")
        if not url:
            raise HTTPException(status_code=400, detail="url required")
        hooks = load_webhooks(config)
        item = {"id": str(uuid.uuid4()), "url": url, "event": event, "created_at": _now()}
        hooks.append(item)
        save_webhooks(config, hooks)
        return item

    @app.post("/api/events")
    async def post_event(request: Request, user=Depends(require_role(config, "admin", "legal", "developer"))):
        event = await request.json()
        event.setdefault("created_at", _now())
        delivered = []
        for hook in load_webhooks(config):
            if hook.get("event") in {event.get("type"), "*"}:
                delivered.append({"id": hook.get("id"), "ok": emit_webhook(hook["url"], event)})
        return {"event": event, "delivered": delivered}

    return app
