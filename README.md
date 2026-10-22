# Posture policies report

Exports your Sysdig posture policies to a CSV file: every policy, its requirements and the controls inside them, one row per control. Handy when you want to review everything in a spreadsheet instead of clicking through each policy in the UI.

You need Python 3.8 or newer and a Sysdig API token. Nothing to install. The script only reads data, it never changes anything in Sysdig.

## Quick start

```bash
export SYSDIG_API_TOKEN="your-token"
python3 posture_policies_report.py --url https://app.us4.sysdig.com --list
python3 posture_policies_report.py --url https://app.us4.sysdig.com -p 52
```

`--list` shows your policies and their IDs. `-p` exports the ones you pick, which is much faster than everything, though big policies still take a while. If you really need everything, use `--all` instead (see below). You get a file called `posture_policies_<date>_<time>.csv` in the folder you ran it from.

You always have to tell the script your region with `--url`. Use the address you open Sysdig with (the one above is US4, as an example). There is no default region. If you don't want to type it every time, set it once:

```bash
export SYSDIG_URL="https://app.us4.sysdig.com"
```

You have to pick at least one `-p` or use `--all`. `-p` is the recommended one if you only need a few policies, though a big policy can still take a while. `--all` takes a few minutes and the file can have hundreds of thousands of rows.

## Options

| Option | What it does |
|---|---|
| `--url URL` | **Required.** Your Sysdig region address. You can also set `SYSDIG_URL`. |
| `--token-file FILE` | Read the token from a file instead of the `SYSDIG_API_TOKEN` variable. Using the variable is the recommended way. |
| `--all` | Export every policy. |
| `-p`, `--policy X` | Export only some policies (see below). Use it as many times as you need. |
| `--list` | Show policy IDs and names, then stop. |
| `-o`, `--output FILE` | Name of the CSV. |
| `--timeout SECONDS` | How long to wait for each request. Default is 120. |

### Picking policies

The examples below assume you set `SYSDIG_URL` as shown above. Use `--list` to see what you have, then `-p` with an ID or part of a name:

```bash
python3 posture_policies_report.py --list

python3 posture_policies_report.py -p 52                 # one policy, by ID
python3 posture_policies_report.py -p 52 -p 156          # two policies
python3 posture_policies_report.py -p "CIS Amazon"       # every policy with that text in its name
```

A number always means the policy ID. Anything else is searched in the names, ignoring upper and lower case. If something doesn't match, the script tells you and stops.

## What's in the CSV

| Column | Meaning |
|---|---|
| `policy_id`, `policy_name`, `policy_description`, `policy_version` | The basics of the policy. The description is only on the first row of each policy. |
| `policy_status` | `Published` or `Draft`, the same status you see in the Sysdig UI. |
| `policy_origin` | `Custom` if someone in your account made it, `Sysdig` if it comes from Sysdig. |
| `policy_author`, `published_date`, `zones` | Who wrote it, when it was published and the zones it's assigned to. |
| `requirement_group`, `requirement_id`, `requirement` | Where the control lives inside the policy. When folders are nested, the group shows the whole path, like `5 Policies > 5.1 RBAC and Service Accounts`. |
| `control_id`, `control_name` | The control. |
| `control_target`, `resource_kind` | What the control checks, like `AWS`, `Linux`, `Kubernetes`. |
| `control_severity` | Severity of the control: High, Medium, Low or Info. |
| `control_enabled` | `Enabled` or `Disabled` for that policy. |
| `control_manual` | `true` if it's a manual control. |
| `id_match`, `note` | How sure we are about the control ID. See the next section. |

## Good to know

**Controls with the same name.** Some controls share a name but have different IDs. The policy only gives the name, so the script works out which control is used in that policy and requirement.

`id_match` shows how it went:

- `unique`: no other control has this name, so there was nothing to choose.
- `resolved`: other controls have the same name, and the script found the right one for this row.
- `ambiguous`: it couldn't tell which one. All possible IDs are in `control_id`, separated by `|`.

**The `note` column** is usually empty. It explains the rows worth a second look:

- An `ambiguous` match.
- A requirement with two controls of the same name, one Enabled and one Disabled. Sysdig doesn't say which ID has which state, so they could be swapped.

Filter the column to non-empty to see only those rows.

**Order.** Policies and requirements keep Sysdig's order. Inside each requirement the controls are sorted by name, so controls with the same name sit next to each other.

**Empty policies.** A requirement with no controls doesn't get a row. A policy with no controls at all still gets one row, so every policy appears in the file.

## If something goes wrong

| Message | What to do |
|---|---|
| `Missing information, nothing was run` | It lists what you forgot: the region (`--url` or `SYSDIG_URL`), the token (`SYSDIG_API_TOKEN` or `--token-file`), or both. |
| `HTTP 401` or `HTTP 403 ... rejected the token` | The token is wrong, expired, or belongs to another region. Check the token and the `--url` address. |
| `No policy matches "..."` | Run `--list` and check the ID or name. |
| `failed after 4 tries` | Sysdig couldn't be reached. Check your `--url` and your network, then try again. |
| `The folder for ... does not exist` | Pick a folder that exists for `-o`. |
