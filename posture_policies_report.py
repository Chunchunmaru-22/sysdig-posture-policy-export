#!/usr/bin/env python3
"""
Sysdig posture policies -> CSV report
=====================================

Exports every posture policy with its requirements and controls into one CSV
(one row per control, per requirement). Python 3.8+, standard library only.

QUICK START
    export SYSDIG_API_TOKEN="your-token"        # Sysdig Secure API token
    python3 posture_policies_report.py --url https://app.us4.sysdig.com --list
    python3 posture_policies_report.py --url https://app.us4.sysdig.com -p 52
                                                # writes posture_policies_<time>.csv

    # or keep the token in a file instead of the environment
    python3 posture_policies_report.py --url https://app.us4.sysdig.com --all --token-file token.txt

REGION
    You must say which Sysdig region to use, there is no default. Use the address
    you open Sysdig with, in --url or in the SYSDIG_URL environment variable.

COMMON OPTIONS
    --url URL                           Your Sysdig region address (required)
    --list                              Show policy IDs and names, then exit
    --all                               Export every policy (big and slow, see README)
    -p, --policy 52                     Only this policy ID. Numbers match the ID
                                        exactly; any other text matches policy
                                        names containing it (not case sensitive).
                                        Repeat it to pick several policies.
    -o, --output report.csv             Output file name

COLUMNS
    policy_*        ID, name, description (first row of each policy only), version, status, origin,
                    author, published date, zones
    requirement     requirement group (folder), requirement ID and name
    control_*       ID, name, target, resource kind, severity, enabled,
                    manual, plus id_match (see below)

NOTES
  * Published/Draft: Sysdig marks each policy active or not. Active policies are
    Published, the others are Draft, the same as in the Sysdig UI.
  * Origin: "Custom" for policies created by your users, "Sysdig" otherwise.
  * The policy API only gives control names, so ID and severity come from
    the controls API, matched by name. Many controls share a name, so a control
    only counts if the API says it belongs to that exact policy and requirement.
    id_match tells you how it went:
        unique       no other control has this name, so there was nothing to choose
        resolved     other controls have the same name, the right one was picked
        ambiguous    several still fit, all their IDs are listed, joined by "|"
    The note column explains in plain words when a row needs a second look:
    an ambiguous match, or a requirement that lists two same-name controls with
    different Enabled/Disabled states (the API does not say which ID has which
    state, so those two states may be swapped). It is empty otherwise.
  * The token is only read from the environment or a file (never from the
    command line, where other users could see it) and is only ever sent to the
    --url host over HTTPS. Redirects are refused.
  * Cells that start with = + - @ get a leading ' so Excel will not run them.
"""

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPException

WORKERS = 4  # big policy downloads: more in parallel make the API cut connections
LOOKUP_WORKERS = 16  # small control lookups can run in parallel much more
RETRIES = 4
PAGE_SIZE = 500

COLUMNS = [
    "policy_id", "policy_name", "policy_description", "policy_version",
    "policy_status", "policy_origin", "policy_author",
    "published_date", "zones",
    "requirement_group", "requirement_id", "requirement",
    "control_id", "control_name", "control_target",
    "resource_kind", "control_severity", "control_enabled", "control_manual", "id_match", "note",
]

NOTE_AMBIGUOUS = ("Several controls share this name and the API does not say which one belongs "
                  "to this requirement, so all their IDs are listed.")
NOTE_STATUS = ("This requirement lists {} controls with this name and their Enabled/Disabled states "
               "differ. The API does not say which ID has which state, so the states may be "
               "swapped between these rows.")


class ApiError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never forward the token to another host


class Api:
    def __init__(self, base_url, token, timeout):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect)

    def get(self, path, **params):
        """GET a JSON document, retrying on timeouts, dropped connections and 5xx/429."""
        url = f"{self.base}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        last = None
        for attempt in range(RETRIES):
            try:
                with self.opener.open(request, timeout=self.timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    raise ApiError(f"HTTP {e.code}: Sysdig rejected the token. Check that the token is correct "
                                   f"and that --url is the region it belongs to ({self.base}).")
                if e.code < 500 and e.code != 429:
                    raise ApiError(f"HTTP {e.code} on {path}")
                last = f"HTTP {e.code}"
            except (urllib.error.URLError, HTTPException, OSError, ValueError) as e:
                last = type(e).__name__
            time.sleep(1 + attempt * 2)
        hint = f" Check the --url address ({self.base}) and your network." if last == "URLError" else ""
        raise ApiError(f"{path} failed after {RETRIES} tries ({last}).{hint}")

    def data(self, path, **params):
        return self.get(path, **params).get("data")

    def pages(self, path):
        """Yield every item of a paginated endpoint.

        The API can return short (or empty) pages, so keep going until the
        reported total has been covered.
        """
        number = 1
        while True:
            page = self.get(path, pageSize=PAGE_SIZE, pageNumber=number)
            yield from page.get("data") or []
            if number * PAGE_SIZE >= int(page.get("totalCount") or 0):
                return
            number += 1


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def safe(value):
    """Make a value CSV friendly and neutralize spreadsheet formulas."""
    if isinstance(value, bool):
        return str(value).lower()
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def iso_date(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).strftime("%Y-%m-%d") if int(ms) > 0 else ""
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def read_token(token_file):
    """Return the token, or "" if there is none."""
    if token_file:
        try:
            with open(token_file) as f:
                token = f.read().strip()
        except OSError as e:
            sys.exit(f"Cannot read token file {token_file}: {e.strerror}")
    else:
        token = os.environ.get("SYSDIG_API_TOKEN", "").strip()
    if any(c.isspace() for c in token):
        sys.exit("The token should be a single line with no spaces.")
    return token


def list_policies(api):
    """Every policy of the account. The list is asked for twice, in one request and page by page,
    so a limit on either one cannot hide policies. Whatever only the pages return is added at the end."""
    policies = list(api.data("/api/cspm/v1/policy/policies/list") or [])
    known = {str(p["id"]) for p in policies}
    try:
        for p in api.pages("/api/cspm/v1/policy/policies/list"):
            if str(p["id"]) not in known:
                known.add(str(p["id"]))
                policies.append(p)
    except (ApiError, KeyError, TypeError, ValueError):
        pass  # the one-request list above is still complete as far as we know
    return policies


def pick_policies(policies, filters):
    """Numbers match a policy ID exactly, other text matches part of a name."""
    if not filters:
        return policies
    chosen = set()
    for text in filters:
        word = text.strip().lower()
        hits = [p["id"] for p in policies
                if (str(p["id"]) == word if word.isdigit() else word in p["name"].lower())]
        if not hits:
            sys.exit(f'No policy matches "{text}". Run with --list to see the policies.')
        chosen.update(hits)
    return [p for p in policies if p["id"] in chosen]


def pmap(func, items, workers=WORKERS):
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(func, items))


def requirements(detail):
    """Yield (group name, requirement) for every requirement of a policy.
    Folders can hold other folders, so the group is the whole path: "5 Policies > 5.1 RBAC"."""
    def walk(folders, path):
        for folder in folders or []:
            name = " > ".join(filter(None, (path, folder.get("name", ""))))
            for req in folder.get("requirements") or []:
                yield name, req
            yield from walk(folder.get("folders"), name)
    yield from walk(detail.get("requirementFolders"), "")


class ControlResolver:
    """Finds the control behind a name. A control only counts if the API says it belongs
    to that policy and requirement, because different controls can share a name."""

    def __init__(self, api, controls):
        self.api = api
        self.by_name = {}
        for c in controls:
            self.by_name.setdefault(c["name"], []).append(c)
        self.where = {}  # control id -> {(policy id, requirement id)}, or None if the lookup failed

    def load_locations(self, details):
        """Fetch the policy/requirement membership of every control the policies mention by name."""
        used = {c["name"] for d in details for _, r in requirements(d) for c in r.get("controls") or []}
        ids = sorted({c["id"] for n in used for c in self.by_name.get(n, [])})
        log(f"Checking where {len(ids)} controls belong...")

        def membership(cid):
            try:
                meta = (self.api.data(f"/api/cspm/v1/policy/controls/view/{cid}") or {}).get("policyRequirementsMeta")
            except ApiError:
                return None  # unknown: it is accepted, but cannot be told apart from same-name controls
            return {(str(m["policyId"]), str(r["id"])) for m in meta or [] for r in m.get("requirementsMeta") or []}

        self.where = dict(zip(ids, pmap(membership, ids, LOOKUP_WORKERS)))
        if None in self.where.values():
            log("Warning: some controls could not be looked up, their rows may be marked ambiguous.")

    def resolve(self, name, policy_id, requirement_id, turn, times):
        """Return (controls, how). This is the turn-th of `times` entries with this name in the requirement."""
        found = self.by_name.get(name, [])
        here = sorted((c for c in found
                       if self.where.get(c["id"]) is None or (policy_id, requirement_id) in self.where[c["id"]]),
                      key=lambda c: int(c["id"]))
        if not here:  # no control with this name belongs to this requirement
            return [], "not_found"
        how = "unique" if len(found) == 1 else "resolved"
        if len(here) == times:  # one control per entry with this name
            return [here[turn]], how
        return here, "ambiguous"


def join(values):
    """Distinct non-empty values as text, joined with | (several only when a match is ambiguous)."""
    texts = (str(v).lower() if isinstance(v, bool) else str(v) for v in values if v not in (None, ""))
    return "|".join(dict.fromkeys(texts))


def build_rows(policy, detail, resolver, stats):
    """Yield one dict per control of the policy. `stats` counts the id_match results."""
    published = iso_date(policy.get("publishedDate"))
    base = {
        "policy_id": policy["id"], "policy_name": policy["name"],
        "policy_description": detail.get("description", ""),
        "policy_version": detail.get("version", ""),
        "policy_status": "Published" if policy.get("isActive") else "Draft",
        "policy_origin": "Custom" if policy.get("isCustom") else "Sysdig",
        "policy_author": detail.get("authors", ""),
        "published_date": published,
        "zones": "; ".join(z.get("name") or z["id"] for z in policy.get("zones") or []),
    }
    empty = True  # a policy with no controls at all still gets one row
    for group, req in requirements(detail):
        where = {"requirement_group": group, "requirement_id": req["id"], "requirement": req.get("name", "")}
        controls = req.get("controls") or []
        listed = {}  # name -> Enabled/Disabled flags of every entry with that name
        for c in controls:
            listed.setdefault(c["name"], []).append(bool(c.get("status")))
        turns = Counter()
        rows = []
        for control in controls:
            name = control["name"]
            matches, how = resolver.resolve(name, policy["id"], req["id"], turns[name], len(listed[name]))
            turns[name] += 1
            if how == "not_found":
                continue
            stats[how] += 1
            note = ""
            if how == "ambiguous":
                note = NOTE_AMBIGUOUS
            elif len(set(listed[name])) > 1:
                note = NOTE_STATUS.format(len(listed[name]))
            rows.append({
                **base, **where,
                "control_id": join(c["id"] for c in matches),
                "control_name": name,
                "control_target": join(c["targetTypeName"] for c in matches),
                "resource_kind": join(c["resourceKind"] for c in matches),
                "control_severity": join(c["severity"] for c in matches),
                "control_enabled": "Enabled" if control.get("status") else "Disabled",
                "control_manual": join(c["isManual"] for c in matches),
                "id_match": how,
                "note": note,
            })
        # the API order inside a requirement looks random: sort by name so same-name controls sit together
        rows.sort(key=lambda r: (r["control_name"].casefold(), int(r["control_id"].split("|")[0])))
        empty = empty and not rows
        yield from rows
    if empty:
        yield base


def main():
    ap = argparse.ArgumentParser(description="Export Sysdig posture policies and controls to CSV.",
                                 epilog="Run with --help or read the top of this file for details.")
    ap.add_argument("--url", default=os.environ.get("SYSDIG_URL"),
                    help="your Sysdig region address, e.g. https://app.us4.sysdig.com (or set SYSDIG_URL)")
    ap.add_argument("--token-file", help="file with the API token (default: SYSDIG_API_TOKEN env var)")
    ap.add_argument("-p", "--policy", action="append", default=[], metavar="TEXT",
                    help="policy ID (number) or part of a name; repeat to pick several")
    ap.add_argument("--all", action="store_true", help="export every policy (a full export is big and takes a few minutes)")
    ap.add_argument("-o", "--output", help="CSV file (default: posture_policies_<time>.csv)")
    ap.add_argument("--list", action="store_true", help="show policy IDs and names, then exit")
    ap.add_argument("--timeout", type=int, default=120, help="seconds per request (default: 120)")
    args = ap.parse_args()

    token = read_token(args.token_file)
    missing = []
    if not args.url:
        missing.append("Sysdig region: add --url with the address you open Sysdig with "
                       "(for example https://app.us4.sysdig.com), or set SYSDIG_URL.")
    if not token:
        missing.append("API token: set SYSDIG_API_TOKEN, or use --token-file FILE.")
    if missing:
        sys.exit("Missing information, nothing was run:\n  - " + "\n  - ".join(missing))
    if urllib.parse.urlparse(args.url).scheme != "https":
        sys.exit("The URL must start with https://")
    if not args.list and not args.all and not args.policy:
        sys.exit("Say which policies to export: use -p with an ID or name, or --all for every policy. "
                 "Run with --list to see them.")
    output = args.output or time.strftime("posture_policies_%Y%m%d_%H%M%S.csv")
    if not os.path.isdir(os.path.dirname(os.path.abspath(output))):
        sys.exit(f"The folder for {output} does not exist.")
    api = Api(args.url, token, args.timeout)

    try:
        everything = list_policies(api)
        if args.list:
            print(f'{"POLICY ID":>9}  POLICY NAME')
            for p in sorted(everything, key=lambda p: p["name"].lower()):
                print(f'{p["id"]:>9}  {p["name"]}')
            return
        policies = pick_policies(everything, args.policy)
        log(f"Reading {len(policies)} policies from {args.url}...")
        details = pmap(lambda p: api.data(f"/api/cspm/v1/policy/posture/policies/{p['id']}",
                                          include_controls="true") or {}, policies)
        log("Reading the controls catalog...")
        resolver = ControlResolver(api, list(api.pages("/api/cspm/v1/policy/controls/search")))
        resolver.load_locations(details)
    except ApiError as e:
        sys.exit(f"Error: {e}")

    stats = Counter()
    rows = 0
    try:
        with open(output, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, COLUMNS)
            writer.writeheader()
            for policy, detail in zip(policies, details):
                for n, row in enumerate(build_rows(policy, detail, resolver, stats)):
                    if n:
                        row["policy_description"] = ""
                    writer.writerow({k: safe(row.get(k)) for k in COLUMNS})
                    rows += 1
    except OSError as e:
        sys.exit(f"Cannot write {output}: {e.strerror}")
    log(f"Done: {rows} rows written to {output}")


if __name__ == "__main__":
    main()
