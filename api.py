#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
    abort,
    Response,
    stream_with_context,
)

# -------------------------------------------------------------------
# Configuration & Helpers
# -------------------------------------------------------------------


def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Flask application factory.
    """
    app = Flask(__name__, static_folder=".", static_url_path="")

    # Default configuration
    app.config.setdefault("ALERT_FILE", "alerts.json")
    app.config.setdefault("BUS_FILE", "attack_bus.json")

    if config:
        app.config.update(config)

    register_routes(app)
    register_error_handlers(app)

    return app


def load_json_safe(path: str, default: Any) -> Any:
    """
    Load JSON from a file, returning 'default' if file is missing
    or corrupted.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def atomic_write_json(path: str, data: Any) -> None:
    """
    Atomic JSON write to reduce risk of corruption when multiple
    processes read/write the same file.
    """
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)


# -------------------------------------------------------------------
# Data Models
# -------------------------------------------------------------------


@dataclass
class AttackMessage:
    """
    Schema for messages posted to /attack and written to BUS_FILE.
    """
    type: str
    icao: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackMessage":
        if not isinstance(data, dict):
            raise ValueError("Payload must be a JSON object")

        attack_type = data.get("type")
        if not isinstance(attack_type, str) or not attack_type.strip():
            raise ValueError("'type' is required and must be a non-empty string")

        icao = data.get("icao")
        if icao is not None and not isinstance(icao, str):
            raise ValueError("'icao' must be a string if provided")

        reserved = {"type", "icao"}
        metadata = {k: v for k, v in data.items() if k not in reserved}

        return cls(type=attack_type.strip(), icao=icao, metadata=metadata)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a flat dict compatible with existing engine expectations.
        """
        base = {"type": self.type}
        if self.icao is not None:
            base["icao"] = self.icao
        base.update(self.metadata)
        return base


# -------------------------------------------------------------------
# Routes & Error Handlers
# -------------------------------------------------------------------


def register_routes(app: Flask) -> None:
    ALERT_FILE = app.config["ALERT_FILE"]
    BUS_FILE = app.config["BUS_FILE"]

    @app.get("/")
    def dashboard():
        """
        Serve the main dashboard page.
        """
        return send_from_directory(app.static_folder, "dashboard.html")

    @app.get("/alerts")
    def alerts():
        """
        Return the current list of alerts from ALERT_FILE.
        Optional: ?limit=N to return only last N alerts.
        """
        alerts: List[Dict[str, Any]] = load_json_safe(ALERT_FILE, [])
        if not isinstance(alerts, list):
            alerts = []

        limit_param = request.args.get("limit")
        if limit_param is not None:
            try:
                limit = max(1, min(int(limit_param), 1000))
                alerts = alerts[-limit:]
            except ValueError:
                pass

        return jsonify(alerts)

    @app.get("/alerts/stream")
    def alerts_stream():
        """
        Server-Sent Events stream of alerts.
        Sends the full alerts list whenever it changes.
        """

        def event_stream():
            last_version = None
            while True:
                time.sleep(1.0)
                alerts = load_json_safe(ALERT_FILE, [])
                if not isinstance(alerts, list):
                    alerts = []

                # Simple "version": length + last timestamp
                last_ts = alerts[-1].get("timestamp", "") if alerts else ""
                version = f"{len(alerts)}:{last_ts}"

                # Emit whenever the version changes
                if version != last_version:
                    last_version = version
                    payload = json.dumps(alerts)
                    # Basic SSE message
                    yield f"data: {payload}\n\n"

        # stream_with_context keeps the request context during streaming
        return Response(
            stream_with_context(event_stream()),
            mimetype="text/event-stream",
        )

    @app.post("/attack")
    def attack():
        """
        Queue an attack into BUS_FILE to be picked up by the IDS engine.
        Body must be JSON with at least: {"type": "SOME_ATTACK"}.
        """
        if not request.is_json:
            abort(400, description="Request must be JSON")

        payload = request.get_json(silent=True)
        if payload is None:
            abort(400, description="Invalid JSON payload")

        try:
            attack_msg = AttackMessage.from_dict(payload)
        except ValueError as exc:
            abort(400, description=str(exc))

        queue: List[Dict[str, Any]] = load_json_safe(BUS_FILE, [])
        if not isinstance(queue, list):
            queue = []

        queue.append(attack_msg.to_dict())
        atomic_write_json(BUS_FILE, queue)

        return jsonify({
            "status": "queued",
            "queue_size": len(queue),
        })

    @app.post("/reset")
    def reset():
        """
        Clear both alerts and queued attacks.
        """
        atomic_write_json(ALERT_FILE, [])
        atomic_write_json(BUS_FILE, [])
        return jsonify({"status": "cleared"})

    @app.get("/health")
    def health():
        """
        Simple health check endpoint for monitoring.
        """
        alerts = load_json_safe(ALERT_FILE, [])
        bus = load_json_safe(BUS_FILE, [])
        return jsonify({
            "status": "ok",
            "alerts_count": len(alerts) if isinstance(alerts, list) else 0,
            "queue_count": len(bus) if isinstance(bus, list) else 0,
        })


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def handle_400(err):
        return jsonify({
            "error": "bad_request",
            "message": getattr(err, "description", "Bad request"),
        }), 400

    @app.errorhandler(404)
    def handle_404(err):
        return jsonify({
            "error": "not_found",
            "message": "Resource not found",
        }), 404

    @app.errorhandler(500)
    def handle_500(err):
        return jsonify({
            "error": "internal_error",
            "message": "Internal server error",
        }), 500


# -------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    app = create_app()
    app.run(host=host, port=port, debug=debug, threaded=True)
    # threaded=True helps with multiple concurrent SSE / normal requests
