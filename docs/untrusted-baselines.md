# Untrusted Baselines

## Why a Separate Interface Exists

A baseline file checked into a pull request is editable by external contributors. If that
document were treated as trusted, a contributor could:

* add a `plugins_used` / `filters_used` entry pointing at a Python file and get the CI
  process to import arbitrary code;
* point wordlist, gibberish-model or exclusion-regex configuration at paths the CI
  process can read but the contributor cannot;
* invent new `hashed_secret` entries, copy an existing hash under another filename, or
  relabel a finding with a different detector type to whitelist newly added secrets;
* flip `is_secret` / `is_verified` to forge an audit decision.

The regular `detect_secrets.core.baseline.load` function intentionally does **all** of the
configuration work above: it exists for baselines that your organization trusts. Never run
it on a document that came from an untrusted branch.

For documents you do not trust, use the explicit opt-in interface instead:

```python
from detect_secrets.core.baseline import load as load_trusted_baseline
from detect_secrets.core.untrusted_baseline import load_untrusted_baseline

# 1. The approved baseline is fetched from the protected branch through a channel the
#    contributor cannot write to, and loaded with the trusted interface.
approved = load_trusted_baseline(approved_baseline_json)

# 2. The candidate document comes straight from the pull request. It is only allowed to
#    *claim* that some findings were already known.
exemptions = load_untrusted_baseline(candidate_baseline_json, approved)

# 3. Scan with the trusted policy that your service configured beforehand, then subtract
#    the approved historical findings exactly like the pre-commit hook does.
fresh = SecretsCollection()
fresh.scan_file(changed_filename)
new_findings = fresh - exemptions
```

The candidate document is **not an approval source**. It supplies nothing more than
findings to be checked against the approved baseline.

## What the Untrusted Loader Guarantees

### No configuration authority

Everything in the candidate other than `version` and `results` -- `plugins_used`,
`filters_used`, `exclude` regexes, `word_list`, gibberish model paths, custom plugin
paths -- is ignored. No Python path referenced by the candidate is imported, no referenced
file is opened, and the global `Settings` object (including the plugin/filter caches) is
neither modified nor temporarily swapped. Your scan runs with exactly the plugins and
filters that were installed before the call.

### Matching is filename + detector type + hash

A candidate finding enters the exemption set only when **all three** match an approved
finding:

* the normalized repository-relative filename;
* the detector `type`;
* the `hashed_secret` digest.

`line_number` is deliberately excluded from the identity: moving a secret to another line
is not a new credential. Consequently, each of the following stays out of the exemption
set and is reported as a new finding:

| Candidate change                                              | Result                |
| ------------------------------------------------------------- | --------------------- |
| New `hashed_secret`                                           | reported as new       |
| Same hash copied to a different file                          | reported as new       |
| Same hash relabeled with a different detector `type`          | reported as new       |
| Approved record deleted from the candidate                    | exemption only shrinks|

"Same hash found" can never become a cross-file whitelist.

### Audit verdicts come from the approved record only

`is_secret` and `is_verified` on exempted findings are copied from the approved
`SecretsCollection`. Whatever the candidate writes for those fields -- `true` or `false`
-- is discarded. Plaintext `secret_value` is never stored in the returned collection and
never appears in its JSON output.

### Strict validation, applied before any collection is built

The whole document is validated first; only an entirely valid document produces a result.
`InvalidBaselineError` is raised when:

* `version` is missing, malformed, or not the supported version;
* `results` is missing, not an object, or a file's findings are not a list;
* a `hashed_secret` is not a 40-character lowercase hexadecimal SHA-1 digest (the
  algorithm detect-secrets currently uses);
* a `line_number` is a boolean, non-integer, zero or negative (the field may be omitted
  entirely, as in slim baseline output);
* a path is absolute, a Windows drive-letter path (`C:\...`), a UNC path
  (`\\server\share` or `//server/share`), contains a NUL byte, or lexically escapes the
  repository root via `..`;
* two file entries normalize to the same path, or the same `(type, hash)` finding appears
  twice in one file -- collisions and duplicates are errors, never resolved by which
  entry came first.

Forward slashes and backslashes are normalized to the same repository-relative form, so
`app\config.py` and `app/config.py` follow identical rules. On failure, both inputs, the
active scan settings and the plugin/filter caches remain exactly as they were, and no
partial exemption set is returned.

## Operational Checklist for Integrators

1. Fetch the approved baseline from the protected branch yourself; do not accept it from
   the pull request payload.
2. Load it with `detect_secrets.core.baseline.load` (or a fixed, trusted plugin
   configuration of your own).
3. Parse the pull request's candidate document as JSON, and hand it to
   `load_untrusted_baseline` together with the approved collection.
4. Treat an `InvalidBaselineError` as a failed check: ask the contributor to regenerate
   the baseline rather than silently accepting part of it.
5. Run your own scan with your own trusted settings, and compute `fresh - exemptions` to
   decide what to alert on.
