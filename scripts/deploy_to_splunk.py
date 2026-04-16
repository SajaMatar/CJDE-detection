#!/usr/bin/env python3
"""
deploy_to_splunk.py

Deploy a Sigma-derived SPL query as a Splunk saved search via the REST API.
Idempotent: if a saved search with the given name already exists, it is
updated in place; otherwise a new one is created.

Usage:
    python deploy_to_splunk.py \
        --url https://splunk.example.com:8089 \
        --token "$SPLUNK_TOKEN" \
        --rule "suspicious_powershell" \
        --query 'index=main sourcetype=WinEventLog:* EventCode=4104 ...' \
        --actions "logevent"

Exit codes:
    0 — saved search created or updated successfully
    1 — any failure (network, auth, Splunk error, invalid args)
"""

import argparse
import sys
from urllib.parse import quote

import requests
from requests.exceptions import RequestException
import urllib3


# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Deploy a Sigma-derived SPL query as a Splunk saved search."
    )

    # Required
    p.add_argument("--url", required=True,
                   help="Splunk management URL, e.g. https://splunk.example.com:8089")
    p.add_argument("--token", required=True, help="Splunk API bearer token")
    p.add_argument("--rule", required=True, help="Saved-search name")
    p.add_argument("--query", required=True, help="SPL search query")

    # Alert actions (comma-separated Splunk action names, e.g. "email,logevent")
    p.add_argument("--actions", default="",
                   help="Comma-separated alert actions (e.g. 'email,logevent'). "
                        "Pass empty string for no actions.")

    # Scheduling
    p.add_argument("--cron", default="*/5 * * * *",
                   help="Cron schedule for the saved search (default: every 5 min)")
    p.add_argument("--earliest", default="-5m",
                   help="Dispatch earliest time (default: -5m)")
    p.add_argument("--latest", default="now",
                   help="Dispatch latest time (default: now)")

    # Alert config
    p.add_argument("--severity", type=int, default=3, choices=[1, 2, 3, 4, 5],
                   help="Alert severity: 1=info, 2=low, 3=normal, 4=high, 5=critical")
    p.add_argument("--alert-threshold", default="0",
                   help="Trigger when result count > threshold (default: 0)")
    p.add_argument("--description",
                   default="Deployed from Sigma rule via GitHub Actions",
                   help="Saved-search description")

    # Splunk context
    p.add_argument("--app", default="search", help="Splunk app context (default: search)")
    p.add_argument("--owner", default="nobody", help="Splunk user context (default: nobody)")

    # TLS
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification (self-signed certs). Use with caution.")
    p.add_argument("--ca-bundle", default=None,
                   help="Path to CA bundle for TLS verification")

    return p.parse_args()


# ----------------------------------------------------------------------------
# Splunk REST helpers
# ----------------------------------------------------------------------------

def endpoint(base_url, app, owner, name=None):
    """Build a Splunk REST endpoint for saved searches."""
    base = base_url.rstrip("/")
    path = f"/servicesNS/{quote(owner)}/{quote(app)}/saved/searches"
    if name:
        path += f"/{quote(name, safe='')}"
    return base + path


def search_exists(session, detail_url, verify):
    """Return True if the saved search exists, False if 404, raise on other errors."""
    r = session.get(detail_url, params={"output_mode": "json"}, verify=verify)
    if r.status_code == 200:
        return True
    if r.status_code == 404:
        return False
    r.raise_for_status()
    return False  # unreachable


def build_payload(args, include_name):
    """
    Build the form-encoded payload for creating/updating a saved search.

    Splunk's REST API requires 'name' on create but rejects it on update
    (since the name is in the URL path), so we toggle it.
    """
    payload = {
        "search": args.query,
        "description": args.description,
        "is_scheduled": "1",
        "cron_schedule": args.cron,
        "dispatch.earliest_time": args.earliest,
        "dispatch.latest_time": args.latest,
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": str(args.alert_threshold),
        "alert.severity": str(args.severity),
        "alert.track": "1",
        "disabled": "0",
    }
    if args.actions:
        payload["actions"] = args.actions
    if include_name:
        payload["name"] = args.rule
    return payload


# ----------------------------------------------------------------------------
# Main deployment logic
# ----------------------------------------------------------------------------

def deploy(args):
    # TLS configuration
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        verify = False
    elif args.ca_bundle:
        verify = args.ca_bundle
    else:
        verify = True

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {args.token}"})

    detail_url = endpoint(args.url, args.app, args.owner, args.rule)
    collection_url = endpoint(args.url, args.app, args.owner)

    # Step 1 — does the saved search already exist?
    try:
        exists = search_exists(session, detail_url, verify)
    except RequestException as e:
        print(f"× ERROR: failed to query existing saved search: {e}", file=sys.stderr)
        return 1

    # Step 2 — pick target URL and payload
    if exists:
        print(f"• Saved search '{args.rule}' exists — updating")
        target_url = detail_url
        payload = build_payload(args, include_name=False)
    else:
        print(f"• Saved search '{args.rule}' not found — creating")
        target_url = collection_url
        payload = build_payload(args, include_name=True)

    # Step 3 — create or update
    try:
        r = session.post(
            target_url,
            data=payload,
            params={"output_mode": "json"},
            verify=verify,
        )
    except RequestException as e:
        print(f"× ERROR: request failed: {e}", file=sys.stderr)
        return 1

    if r.status_code in (200, 201):
        action = "updated" if exists else "created"
        print(f"✓ Saved search '{args.rule}' {action} successfully (HTTP {r.status_code})")
        return 0

    # Error path — surface the Splunk error body
    print(f"× ERROR: Splunk returned HTTP {r.status_code}", file=sys.stderr)
    try:
        body = r.json()
        messages = body.get("messages", [])
        for m in messages:
            print(f"    [{m.get('type', 'ERROR')}] {m.get('text', '')}", file=sys.stderr)
        if not messages:
            print(body, file=sys.stderr)
    except ValueError:
        print(r.text, file=sys.stderr)
    return 1


def main():
    args = parse_args()
    sys.exit(deploy(args))


if __name__ == "__main__":
    main()
