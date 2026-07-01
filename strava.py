#!/usr/bin/env python3
"""Local Strava OAuth and API helper.

This script intentionally uses only Python's standard library so the connector
works before any project dependencies exist.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
TOKEN_PATH = ROOT / ".strava_tokens.json"
API_BASE = "https://www.strava.com/api/v3"
AUTH_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8787/callback"
DEFAULT_SCOPE = "read,activity:read_all"


class StravaError(RuntimeError):
    pass


def load_env() -> dict[str, str]:
    env = dict(os.environ)
    if ENV_PATH.exists():
        for raw_line in ENV_PATH.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    return env


def require_config() -> tuple[str, str, str]:
    env = load_env()
    client_id = env.get("STRAVA_CLIENT_ID", "").strip()
    client_secret = env.get("STRAVA_CLIENT_SECRET", "").strip()
    redirect_uri = env.get("STRAVA_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip()

    if not client_id or not client_secret:
        raise StravaError(
            "Missing STRAVA_CLIENT_ID or STRAVA_CLIENT_SECRET. Copy .env.example "
            "to .env and fill in your Strava API app credentials."
        )
    return client_id, client_secret, redirect_uri


def load_tokens() -> dict[str, Any]:
    if not TOKEN_PATH.exists():
        raise StravaError("No token file found. Run `python3 strava.py auth` first.")
    return json.loads(TOKEN_PATH.read_text())


def save_tokens(tokens: dict[str, Any]) -> None:
    TOKEN_PATH.write_text(json.dumps(tokens, indent=2, sort_keys=True) + "\n")
    try:
        TOKEN_PATH.chmod(0o600)
    except OSError:
        pass


def post_form(url: str, data: dict[str, Any]) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(url, data=encoded, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    return request_json(request)


def request_json(request: urllib.request.Request) -> dict[str, Any] | list[Any]:
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode()
            if not body:
                return {}
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise StravaError(f"Strava API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise StravaError(f"Could not reach Strava API: {exc.reason}") from exc


def exchange_code(code: str) -> dict[str, Any]:
    client_id, client_secret, _redirect_uri = require_config()
    tokens = post_form(
        TOKEN_URL,
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
        },
    )
    if not isinstance(tokens, dict) or "access_token" not in tokens:
        raise StravaError(f"Unexpected token response: {tokens!r}")
    save_tokens(tokens)
    return tokens


def refresh_if_needed(tokens: dict[str, Any]) -> dict[str, Any]:
    expires_at = int(tokens.get("expires_at", 0))
    if expires_at > int(time.time()) + 300:
        return tokens

    client_id, client_secret, _redirect_uri = require_config()
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise StravaError("Token file is missing refresh_token. Run auth again.")

    refreshed = post_form(
        TOKEN_URL,
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )
    if not isinstance(refreshed, dict) or "access_token" not in refreshed:
        raise StravaError(f"Unexpected refresh response: {refreshed!r}")

    merged = {**tokens, **refreshed}
    save_tokens(merged)
    return merged


def api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    tokens = refresh_if_needed(load_tokens())
    query = ""
    if params:
        clean_params = {key: value for key, value in params.items() if value is not None}
        query = "?" + urllib.parse.urlencode(clean_params)
    request = urllib.request.Request(f"{API_BASE}{path}{query}", method="GET")
    request.add_header("Authorization", f"Bearer {tokens['access_token']}")
    return request_json(request)


def callback_server(port: int) -> str:
    result: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib API name
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "error" in params:
                result["error"] = params["error"][0]
                body = b"Strava authorization was denied. You can close this tab."
                status = 400
            elif "code" in params:
                result["code"] = params["code"][0]
                result["scope"] = params.get("scope", [""])[0]
                body = b"Strava authorization complete. You can close this tab."
                status = 200
            else:
                body = b"Missing Strava authorization code."
                status = 400

            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", port), Handler)
    while "code" not in result and "error" not in result:
        server.handle_request()
    server.server_close()

    if "error" in result:
        raise StravaError(f"Authorization failed: {result['error']}")
    if result.get("scope"):
        print(f"Granted scope: {result['scope']}")
    return result["code"]


def run_auth(args: argparse.Namespace) -> None:
    client_id, _client_secret, redirect_uri = require_config()
    parsed_redirect = urllib.parse.urlparse(redirect_uri)
    port = parsed_redirect.port or 8787
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "approval_prompt": args.approval_prompt,
        "scope": args.scope,
        "state": "local-strava-connector",
    }
    url = f"{AUTH_URL}?{urllib.parse.urlencode(auth_params)}"
    print("Open this Strava authorization URL:")
    print(url)
    if not args.no_browser:
        webbrowser.open(url)
    print(f"Waiting for callback on {redirect_uri} ...")
    code = callback_server(port)
    tokens = exchange_code(code)
    athlete = tokens.get("athlete", {})
    name = " ".join(
        part for part in [athlete.get("firstname"), athlete.get("lastname")] if part
    )
    print(f"Authorized {name or 'athlete'}; tokens saved to {TOKEN_PATH.name}.")


def run_athlete(_args: argparse.Namespace) -> None:
    print(json.dumps(api_get("/athlete"), indent=2, sort_keys=True))


def get_activities(limit: int, before: int | None, after: int | None) -> list[dict[str, Any]]:
    activities: list[dict[str, Any]] = []
    page = 1
    per_page = min(200, max(1, limit))
    while len(activities) < limit:
        batch = api_get(
            "/athlete/activities",
            {"page": page, "per_page": per_page, "before": before, "after": after},
        )
        if not isinstance(batch, list):
            raise StravaError(f"Unexpected activities response: {batch!r}")
        if not batch:
            break
        activities.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
    return activities[:limit]


def run_activities(args: argparse.Namespace) -> None:
    activities = get_activities(args.limit, args.before, args.after)
    for activity in activities:
        distance_km = float(activity.get("distance", 0)) / 1000
        moving_minutes = int(activity.get("moving_time", 0)) / 60
        print(
            f"{activity.get('start_date_local', '')[:10]}  "
            f"{activity.get('sport_type') or activity.get('type', ''):<18} "
            f"{distance_km:7.2f} km  {moving_minutes:6.1f} min  "
            f"{activity.get('name', '')}"
        )


def run_export_activities(args: argparse.Namespace) -> None:
    activities = get_activities(args.limit, args.before, args.after)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.suffix.lower() == ".csv":
        fields = [
            "id",
            "name",
            "sport_type",
            "type",
            "start_date",
            "start_date_local",
            "distance",
            "moving_time",
            "elapsed_time",
            "total_elevation_gain",
            "average_speed",
            "max_speed",
            "average_heartrate",
            "max_heartrate",
        ]
        with output.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for activity in activities:
                writer.writerow({field: activity.get(field) for field in fields})
    else:
        output.write_text(json.dumps(activities, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {len(activities)} activities to {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Connect to the Strava API.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    auth = subparsers.add_parser("auth", help="Run local OAuth authorization.")
    auth.add_argument("--scope", default=DEFAULT_SCOPE)
    auth.add_argument("--approval-prompt", default="auto", choices=["auto", "force"])
    auth.add_argument("--no-browser", action="store_true")
    auth.set_defaults(func=run_auth)

    athlete = subparsers.add_parser("athlete", help="Print authenticated athlete JSON.")
    athlete.set_defaults(func=run_athlete)

    activities = subparsers.add_parser("activities", help="Print recent activities.")
    activities.add_argument("--limit", type=int, default=20)
    activities.add_argument("--before", type=int, help="Unix timestamp upper bound.")
    activities.add_argument("--after", type=int, help="Unix timestamp lower bound.")
    activities.set_defaults(func=run_activities)

    export = subparsers.add_parser("export-activities", help="Export activities.")
    export.add_argument("--limit", type=int, default=100)
    export.add_argument("--before", type=int, help="Unix timestamp upper bound.")
    export.add_argument("--after", type=int, help="Unix timestamp lower bound.")
    export.add_argument("--output", default="data/activities.json")
    export.set_defaults(func=run_export_activities)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except StravaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
