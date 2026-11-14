"""
Loading findings from an *untrusted* baseline document.

A baseline file that an external contributor can modify (e.g. ``.secrets.baseline`` in a
pull request) is only allowed to *claim* that some findings were previously known. It is
not a source of configuration, and it is not an approval: the approved findings come from
a :class:`~detect_secrets.core.secrets_collection.SecretsCollection` that the caller
loaded from a trusted location (such as a protected branch).

Unlike :func:`detect_secrets.core.baseline.load`, this code path:

* never imports plugin/filter paths, never reads wordlist/model/exclusion paths referenced
  by the candidate, and never configures (or even temporarily mutates) the global
  :class:`~detect_secrets.settings.Settings` or its caches -- scanning continues to use
  whatever trusted policies the caller installed beforehand;
* only admits a candidate finding when its filename, detector type and hashed secret all
  match an approved finding (line numbers are allowed to drift);
* copies ``is_secret`` / ``is_verified`` verdicts from the approved record, so a candidate
  document cannot forge audit decisions, and never stores plaintext secret values.

The returned collection is meant to be subtracted from fresh scan results, so that only
the already-approved findings are suppressed.
"""
import hashlib
import re
from typing import Any
from typing import cast
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Set
from typing import Tuple

from ..__version__ import VERSION
from ..exceptions import InvalidBaselineError
from ..util.path import convert_local_os_path
from ..util.semver import Version
from .potential_secret import PotentialSecret
from .secrets_collection import SecretsCollection


# The only baseline format this trust boundary accepts. Older baselines would have to be
# upgraded through the trusted `baseline.load` path first (upgrades themselves may import
# configured plugins, which is precisely what we refuse to do with untrusted input).
SUPPORTED_VERSION = VERSION

# detect-secrets hashes secrets with SHA-1 (see ``PotentialSecret.hash_secret``): the
# digest is stored as a lowercase hexadecimal string.
HASHED_SECRET_HEX_LENGTH = hashlib.sha1(b'').digest_size * 2
_LOWERCASE_HEX = re.compile(r'^[0-9a-f]+$')
_WINDOWS_DRIVE = re.compile(r'^[a-zA-Z]:')


class _CandidateRecord(NamedTuple):
    type: str
    hashed_secret: str
    # 0 means "no line number provided" (e.g. slim baseline output).
    line_number: int


def load_untrusted_baseline(
    candidate: Dict[str, Any],
    approved: SecretsCollection,
) -> SecretsCollection:
    """
    Extract the subset of an untrusted candidate baseline that is backed by an approved
    finding, for use as the set of historical findings to exclude from fresh scan results.

    :param candidate: parsed JSON of the baseline document supplied by the untrusted party
        (e.g. the PR's version of ``.secrets.baseline``).
    :param approved: findings already approved through a trusted channel, typically loaded
        with :func:`detect_secrets.core.baseline.load` from the protected branch.

    :raises InvalidBaselineError: if the candidate document is structurally invalid,
        references paths outside the repository root, or contains colliding/duplicate
        entries. On failure, neither input, the global settings nor the plugin/filter
        caches are modified, and no partial result is returned.
    """
    # All validation happens against local data structures first. Only once the whole
    # document has been accepted do we construct the output, so a malformed record at the
    # end of the list cannot leave behind half a result.
    candidate_records = _parse_candidate(candidate)
    approved_index = _index_approved(approved)

    exemptions = SecretsCollection()
    for normalized_filename, records in candidate_records.items():
        for record in records:
            approved_secret = approved_index.get(
                (normalized_filename, record.type, record.hashed_secret),
            )
            if approved_secret is None:
                # New hash, copied-to-another-file secret, or switched detector type:
                # the candidate cannot self-approve these, so they stay out of the
                # exemption set and will resurface as fresh findings.
                continue

            data: Dict[str, Any] = {
                'type': record.type,
                'filename': normalized_filename,
                'hashed_secret': record.hashed_secret,
            }
            if record.line_number:
                data['line_number'] = record.line_number

            secret = PotentialSecret.load_secret_from_dict(data)
            # Audit verdicts come exclusively from the approved record; anything the
            # candidate says in `is_secret` / `is_verified` is ignored.
            secret.is_secret = approved_secret.is_secret
            secret.is_verified = approved_secret.is_verified

            # Store paths in the OS-native form, mirroring
            # `SecretsCollection.load_from_baseline`, so set subtraction against freshly
            # scanned collections works on every platform.
            exemptions[convert_local_os_path(normalized_filename)].add(secret)

    return exemptions


def _parse_candidate(
    candidate: Dict[str, Any],
) -> Dict[str, List[_CandidateRecord]]:
    if not isinstance(candidate, dict):
        raise InvalidBaselineError(
            f'candidate baseline must be a JSON object, got {type(candidate).__name__}',
        )

    _validate_version(candidate.get('version'))

    results = candidate.get('results')
    if not isinstance(results, dict):
        raise InvalidBaselineError(
            'candidate baseline has no valid "results" object',
        )

    # Note: `plugins_used`, `filters_used`, `exclude`, `word_list` and any other
    # configuration sections are intentionally never read -- they carry no authority here.

    parsed: Dict[str, List[_CandidateRecord]] = {}
    normalized_files: Set[str] = set()
    for raw_filename, raw_records in results.items():
        normalized_filename = _validate_relative_path(raw_filename, 'results key')
        if normalized_filename in normalized_files:
            raise InvalidBaselineError(
                f'results contain multiple file entries that normalize to the same '
                f'repository-relative path: {normalized_filename}',
            )
        normalized_files.add(normalized_filename)

        if not isinstance(raw_records, list):
            raise InvalidBaselineError(
                f'results["{raw_filename}"] must be a list of findings',
            )

        seen_findings: Set[Tuple[str, str]] = set()
        records: List[_CandidateRecord] = []
        for index, raw_record in enumerate(raw_records):
            where = f'results["{raw_filename}"][{index}]'
            if not isinstance(raw_record, dict):
                raise InvalidBaselineError(f'{where} must be a JSON object')

            record_type = _validate_type(raw_record.get('type'), where)
            hashed_secret = _validate_hashed_secret(
                raw_record.get('hashed_secret'),
                where,
            )
            line_number = _validate_line_number(raw_record.get('line_number'), where)

            identity = (record_type, hashed_secret)
            if identity in seen_findings:
                raise InvalidBaselineError(
                    f'{where} duplicates an earlier finding of the same type and hash; '
                    'duplicate entries are not resolved by ordering',
                )
            seen_findings.add(identity)

            records.append(
                _CandidateRecord(
                    type=record_type,
                    hashed_secret=hashed_secret,
                    line_number=line_number,
                ),
            )

        parsed[normalized_filename] = records

    return parsed


def _validate_version(raw_version: Any) -> None:
    if not isinstance(raw_version, str):
        raise InvalidBaselineError(
            f'candidate baseline "version" must be a string, got '
            f'{type(raw_version).__name__}',
        )

    try:
        candidate_version = Version(raw_version)
    except ValueError:
        raise InvalidBaselineError(
            f'candidate baseline has malformed "version": {raw_version!r}',
        )

    if candidate_version != Version(SUPPORTED_VERSION):
        raise InvalidBaselineError(
            f'candidate baseline version {raw_version!r} is not supported; expected '
            f'{SUPPORTED_VERSION!r} (upgrade trusted baselines via baseline.load first)',
        )


def _validate_type(raw_type: Any, where: str) -> str:
    if not isinstance(raw_type, str) or not raw_type:
        raise InvalidBaselineError(f'{where}: "type" must be a non-empty string')
    return raw_type


def _validate_hashed_secret(raw_hash: Any, where: str) -> str:
    if not isinstance(raw_hash, str):
        raise InvalidBaselineError(
            f'{where}: "hashed_secret" must be a {HASHED_SECRET_HEX_LENGTH}-character '
            'lowercase hexadecimal SHA-1 digest',
        )

    if len(raw_hash) != HASHED_SECRET_HEX_LENGTH or not _LOWERCASE_HEX.fullmatch(raw_hash):
        raise InvalidBaselineError(
            f'{where}: "hashed_secret" {raw_hash!r} is not a '
            f'{HASHED_SECRET_HEX_LENGTH}-character lowercase hexadecimal SHA-1 digest',
        )

    return raw_hash


def _validate_line_number(raw_line_number: Any, where: str) -> int:
    if raw_line_number is None:
        # Slim baselines omit line numbers entirely.
        return 0

    # `bool` is a subclass of `int`, so check it explicitly: True/False are not line
    # numbers, and neither are zero or negative integers.
    if isinstance(raw_line_number, bool) or not isinstance(raw_line_number, int):
        raise InvalidBaselineError(
            f'{where}: "line_number" must be a positive integer when provided',
        )

    if raw_line_number <= 0:
        raise InvalidBaselineError(
            f'{where}: "line_number" must be a positive integer, got {raw_line_number}',
        )

    return cast(int, raw_line_number)


def _validate_relative_path(raw_path: Any, where: str) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise InvalidBaselineError(f'{where}: path must be a non-empty string')

    if '\x00' in raw_path:
        raise InvalidBaselineError(f'{where}: path contains a NUL byte: {raw_path!r}')

    # Reject Windows drive-letter paths (e.g. `C:\...`) and UNC paths (`\\server\share`,
    # `//server/share`) before any normalization -- they can never be repository-relative.
    if _WINDOWS_DRIVE.match(raw_path):
        raise InvalidBaselineError(
            f'{where}: drive-letter paths are not repository-relative: {raw_path!r}',
        )
    if raw_path.startswith(('\\\\', '//')):
        raise InvalidBaselineError(
            f'{where}: UNC paths are not repository-relative: {raw_path!r}',
        )

    # Treat both POSIX and Windows separators by the same repository-relative rule.
    normalized = raw_path.replace('\\', '/')
    if normalized.startswith('/'):
        raise InvalidBaselineError(
            f'{where}: absolute paths are not repository-relative: {raw_path!r}',
        )

    # Lexically collapse `.` / `..` without touching the filesystem (and therefore without
    # following symlinks).
    parts: List[str] = []
    for part in normalized.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if not parts:
                raise InvalidBaselineError(
                    f'{where}: path escapes the repository root: {raw_path!r}',
                )
            parts.pop()
            continue
        parts.append(part)

    if not parts:
        raise InvalidBaselineError(
            f'{where}: path does not name a file inside the repository: {raw_path!r}',
        )

    return '/'.join(parts)


def _index_approved(
    approved: SecretsCollection,
) -> Dict[Tuple[str, str, str], PotentialSecret]:
    if not isinstance(approved, SecretsCollection):
        raise InvalidBaselineError(
            'approved baseline must be a SecretsCollection loaded from a trusted source',
        )

    index: Dict[Tuple[str, str, str], PotentialSecret] = {}
    for filename, secret in approved:
        normalized_filename = filename.replace('\\', '/')
        index[(normalized_filename, secret.type, secret.secret_hash)] = secret

    return index
