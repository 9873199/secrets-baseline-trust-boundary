"""
Tests for the untrusted-baseline trust boundary.

Every test here is fully offline: only built-in detectors run against synthetic fake
credentials, and the global `responses` mock (see tests/conftest.py) blocks any network
verification attempt.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest

from detect_secrets import SecretsCollection
from detect_secrets.__version__ import VERSION
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.untrusted_baseline import load_untrusted_baseline
from detect_secrets.exceptions import InvalidBaselineError
from detect_secrets.settings import get_filters
from detect_secrets.settings import get_plugins
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings


# Synthetic, well-known fake credentials (AWS documentation example keys). No real
# secrets are used anywhere in this test module.
OLD_KEY = 'AKIAIOSFODNN7EXAMPLE'
NEW_KEY = 'AKIAI44QH8DHBEXAMPLE'


def _hash(secret: str) -> str:
    return PotentialSecret.hash_secret(secret)


def _candidate_record(
    secret: str,
    type_: str = 'AWS Access Key',
    line_number: object = 1,
    **extra: object,
) -> dict:
    record = {
        'type': type_,
        'hashed_secret': _hash(secret),
        'line_number': line_number,
    }
    record.update(extra)
    return record


def _scan(cwd: Path, *relative_paths: str) -> SecretsCollection:
    # Mirror the real pre-commit flow: both collections are built with repository-
    # relative paths, so PotentialSecret filenames are comparable across collections.
    with transient_settings({
        'plugins_used': [{'name': 'AWSKeyDetector'}],
    }):
        old_cwd = os.getcwd()
        os.chdir(cwd)
        try:
            secrets = SecretsCollection()
            for relative_path in relative_paths:
                secrets.scan_file(relative_path)
        finally:
            os.chdir(old_cwd)
    return secrets


@pytest.fixture
def repository(tmp_path: Path):
    """A synthetic repository in its *approved* (pre-PR) state."""
    app = tmp_path / 'app'
    app.mkdir()
    (app / 'config.py').write_text(
        '# configuration\n'
        f"aws_access_key = '{OLD_KEY}'\n",
    )
    return tmp_path


EVIL_PLUGIN = """
# A "plugin" whose mere import has an observable side effect: every import increments a
# counter file. If the untrusted loader ever imports this file (or lets the global
# settings do so), the counter file appears and advances.
import pathlib

counter = pathlib.Path(__file__).with_name('evil_plugin.counter')
counter.write_text(str(int(counter.read_text()) + 1) if counter.exists() else '1')


class EvilDetector:
    secret_type = 'Evil'
"""


class TestEndToEndScanChain:
    """The real scanning chain: fresh scan minus untrusted-but-approved exemptions."""

    def test_approved_findings_suppressed_new_findings_remain(self, repository: Path):
        # 1. The approved baseline comes from a trusted scan of the protected branch.
        approved = _scan(repository, 'app/config.py')
        assert len(approved) == 1
        approved_secret = next(iter(approved[str(Path('app/config.py'))]))
        # Record trusted audit decisions on the approved finding.
        approved_secret.is_secret = True
        approved_secret.is_verified = True

        # 2. The PR shifts the old secret down a line, adds a brand new secret, and
        #    copies the old key into another file.
        (repository / 'app' / 'config.py').write_text(
            '# new header added by the PR\n'
            '# configuration\n'
            f"aws_access_key = '{OLD_KEY}'\n",
        )
        (repository / 'app' / 'new_secret.py').write_text(
            f"deploy_token = '{NEW_KEY}'\n",
        )
        docs = repository / 'docs'
        docs.mkdir()
        (docs / 'notes.txt').write_text(f"key = '{OLD_KEY}'\n")

        fresh = _scan(repository, 'app/config.py', 'app/new_secret.py', 'docs/notes.txt')
        assert len(fresh) == 3

        # 3. The candidate baseline is attacker-controlled JSON. It even ships plugin /
        #    filter import paths, exclusion regexes and a wordlist path: none of which
        #    carry any configuration authority.
        evil_plugin = repository / 'evil_plugin.py'
        evil_plugin.write_text(EVIL_PLUGIN)
        counter = repository / 'evil_plugin.counter'

        # Sanity check: the side-effect mechanism itself works when the file is imported.
        spec = importlib.util.spec_from_file_location('evil_plugin_sanity', evil_plugin)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert counter.read_text() == '1'
        counter.unlink()

        candidate = {
            'version': VERSION,
            'plugins_used': [{
                'name': 'EvilDetector',
                'path': f'file:///{evil_plugin}',
            }],
            'filters_used': [{
                'path': f'file:///{evil_plugin}::should_exclude_secret',
            }],
            'exclude': {'files': '.*', 'lines': '.*'},
            'word_list': {'file': str(repository / 'wordlist.txt'), 'hash': 'deadbeef'},
            'results': {
                # Line number drifted (2 -> 3) and audit flags are forged: the loader
                # must still match it, but keep the approved verdicts.
                'app/config.py': [_candidate_record(
                    OLD_KEY,
                    line_number=3,
                    is_secret=False,
                    is_verified=False,
                )],
                # Newly introduced hash: not approved.
                'app/new_secret.py': [_candidate_record(NEW_KEY, line_number=1)],
                # Same hash copied to another file: not a cross-file whitelist.
                'docs/notes.txt': [_candidate_record(OLD_KEY, line_number=1)],
                # Switched detector type for the same hash: not approved either.
                'app/config.py.bak': [_candidate_record(OLD_KEY, type_='Fake Type')],
            },
        }

        settings_before = get_settings().json()
        candidate_before = copy.deepcopy(candidate)
        approved_before = approved.json()

        exemptions = load_untrusted_baseline(candidate, approved)

        # 4. Only the genuinely approved finding enters the exemption set.
        assert len(exemptions) == 1
        exempted = next(iter(exemptions[str(Path('app/config.py'))]))
        assert exempted.secret_hash == _hash(OLD_KEY)
        # Verdicts are inherited from the approved record, never from the candidate.
        assert exempted.is_secret is True
        assert exempted.is_verified is True
        # No plaintext secret ever gets stored or serialized.
        assert exempted.secret_value is None
        serialized = json.dumps(exemptions.json())
        assert 'secret_value' not in serialized
        assert OLD_KEY not in serialized

        # 5. Existing collection subtraction does the actual alerting decision.
        remaining = fresh - exemptions
        # The approved old finding is fully suppressed...
        assert not remaining[str(Path('app/config.py'))]
        # ...while the new hash and the cross-file copy are still reported.
        assert len(remaining) == 2
        remaining_hashes = {
            secret.secret_hash
            for file_secrets in remaining.data.values()
            for secret in file_secrets
        }
        assert remaining_hashes == {_hash(NEW_KEY), _hash(OLD_KEY)}

        # 6. The candidate's plugin/filter paths were never executed.
        assert not counter.exists()

        # 7. Neither input nor the global settings were mutated.
        assert candidate == candidate_before
        assert approved.json() == approved_before
        assert get_settings().json() == settings_before


class TestMatchingRules:
    @staticmethod
    def _approved(tmp_path: Path) -> SecretsCollection:
        approved = SecretsCollection()
        approved[str(Path('app/config.py'))].add(
            PotentialSecret(
                type='AWS Access Key',
                filename=str(Path('app/config.py')),
                secret=OLD_KEY,
                line_number=2,
                is_secret=True,
                is_verified=True,
            ),
        )
        return approved

    def test_line_number_drift_is_still_exempt(self, tmp_path):
        approved = self._approved(tmp_path)
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(OLD_KEY, line_number=99)],
            },
        }

        exemptions = load_untrusted_baseline(candidate, approved)
        assert len(exemptions) == 1

    def test_backslash_and_forward_slash_paths_match_by_same_rule(self, tmp_path):
        approved = self._approved(tmp_path)
        candidate = {
            'version': VERSION,
            'results': {
                # Deliberately use the "other" separator, regardless of host OS.
                'app\\config.py': [_candidate_record(OLD_KEY, line_number=2)],
            },
        }

        exemptions = load_untrusted_baseline(candidate, approved)
        assert len(exemptions) == 1
        exempted_file = next(iter(exemptions.files))
        assert exempted_file == str(Path('app/config.py'))

    def test_new_hash_is_not_exempt(self, tmp_path):
        approved = self._approved(tmp_path)
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(NEW_KEY)],
            },
        }

        assert len(load_untrusted_baseline(candidate, approved)) == 0

    def test_same_hash_in_another_file_is_not_exempt(self, tmp_path):
        approved = self._approved(tmp_path)
        candidate = {
            'version': VERSION,
            'results': {
                'docs/notes.txt': [_candidate_record(OLD_KEY)],
            },
        }

        assert len(load_untrusted_baseline(candidate, approved)) == 0

    def test_switched_detector_type_is_not_exempt(self, tmp_path):
        approved = self._approved(tmp_path)
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(OLD_KEY, type_='Some Other Detector')],
            },
        }

        assert len(load_untrusted_baseline(candidate, approved)) == 0

    def test_removing_records_only_reduces_exemptions(self, tmp_path):
        approved = self._approved(tmp_path)
        candidate = {'version': VERSION, 'results': {}}

        exemptions = load_untrusted_baseline(candidate, approved)
        assert len(exemptions) == 0
        # The approved collection itself is untouched.
        assert len(approved) == 1

    def test_candidate_cannot_forge_audit_flags_in_either_direction(self, tmp_path):
        approved = self._approved(tmp_path)
        for forged in (False, True):
            candidate = {
                'version': VERSION,
                'results': {
                    'app/config.py': [_candidate_record(
                        OLD_KEY,
                        is_secret=forged,
                        is_verified=forged,
                    )],
                },
            }

            exempted = next(iter(
                load_untrusted_baseline(candidate, approved)[str(Path('app/config.py'))],
            ))
            assert exempted.is_secret is True
            assert exempted.is_verified is True

    def test_unverified_approved_verdict_is_also_carried_over(self, tmp_path):
        approved = SecretsCollection()
        approved['app/config.py'].add(
            PotentialSecret(
                type='AWS Access Key',
                filename='app/config.py',
                secret=OLD_KEY,
                line_number=2,
            ),
        )
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(
                    OLD_KEY,
                    is_secret=True,
                    is_verified=True,
                )],
            },
        }

        exempted = next(iter(
            load_untrusted_baseline(candidate, approved)[str(Path('app/config.py'))],
        ))
        assert exempted.is_secret is None
        assert exempted.is_verified is False

    def test_slim_baseline_without_line_numbers_is_accepted(self, tmp_path):
        approved = self._approved(tmp_path)
        record = _candidate_record(OLD_KEY)
        record.pop('line_number')
        candidate = {'version': VERSION, 'results': {'app/config.py': [record]}}

        assert len(load_untrusted_baseline(candidate, approved)) == 1


class TestStructuralValidation:
    @pytest.mark.parametrize(
        'candidate',
        (
            {'results': {}},                                   # missing version
            {'version': 1.5, 'results': {}},                   # non-string version
            {'version': '1.4.0', 'results': {}},               # unsupported version
            {'version': '2.0.0', 'results': {}},               # newer version
            {'version': 'not-a-version', 'results': {}},       # malformed version
            {'version': VERSION},                              # missing results
            {'version': VERSION, 'results': []},               # results not an object
            {'version': VERSION, 'results': {'a.py': {}}},     # records not a list
            {'version': VERSION, 'results': {'a.py': [[]]}},   # record not an object
        ),
    )
    def test_bad_document_structure(self, candidate, tmp_path):
        approved = SecretsCollection()
        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline(candidate, approved)

    @pytest.mark.parametrize(
        'bad_hash',
        (
            'a' * 39,                                  # too short
            'a' * 41,                                  # too long
            'A' * 40,                                  # uppercase hex
            'g' * 40,                                  # non-hex character
            40 * 'a' + ' ',                            # trailing whitespace
            12345,                                     # non-string
            None,                                      # missing
        ),
    )
    def test_bad_hashed_secret(self, bad_hash, tmp_path):
        candidate = {
            'version': VERSION,
            'results': {'a.py': [{
                'type': 'AWS Access Key',
                'hashed_secret': bad_hash,
                'line_number': 1,
            }]},
        }
        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline(candidate, SecretsCollection())

    @pytest.mark.parametrize('bad_line_number', (True, False, 0, -1, -100, 1.5, '3'))
    def test_bad_line_number(self, bad_line_number):
        candidate = {
            'version': VERSION,
            'results': {'a.py': [{
                'type': 'AWS Access Key',
                'hashed_secret': 'a' * 40,
                'line_number': bad_line_number,
            }]},
        }
        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline(candidate, SecretsCollection())

    @pytest.mark.parametrize(
        'bad_path',
        (
            '../escape.py',
            'a/../../escape.py',
            '..\\escape.py',
            'a/../..',
            '/etc/passwd',
            '\\windows\\system32',
            'C:\\secret.py',
            'c:/secret.py',
            '\\\\server\\share\\secret.py',
            '//server/share/secret.py',
            '',
            '.',
            'a/../',
            'bad\0name.py',
        ),
    )
    def test_paths_outside_root_are_rejected(self, bad_path):
        candidate = {
            'version': VERSION,
            'results': {bad_path: [{
                'type': 'AWS Access Key',
                'hashed_secret': 'a' * 40,
                'line_number': 1,
            }]},
        }
        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline(candidate, SecretsCollection())

    @pytest.mark.parametrize(
        'good_path',
        (
            'app/config.py',
            '.\\app\\config.py',
            'app\\config.py',
            './app/config.py',
            './c.py',
            'a/../c.py',
        ),
    )
    def test_valid_relative_paths_are_normalized(self, good_path):
        approved = SecretsCollection()
        approved['app/config.py'].add(
            PotentialSecret('AWS Access Key', 'app/config.py', OLD_KEY, line_number=1),
        )
        approved['c.py'].add(
            PotentialSecret('AWS Access Key', 'c.py', OLD_KEY, line_number=1),
        )
        candidate = {
            'version': VERSION,
            'results': {good_path: [_candidate_record(OLD_KEY)]},
        }

        assert len(load_untrusted_baseline(candidate, approved)) == 1

    def test_missing_or_empty_type_is_rejected(self):
        for bad_type in (None, '', 42):
            candidate = {
                'version': VERSION,
                'results': {'a.py': [{
                    'type': bad_type,
                    'hashed_secret': 'a' * 40,
                    'line_number': 1,
                }]},
            }
            with pytest.raises(InvalidBaselineError):
                load_untrusted_baseline(candidate, SecretsCollection())

    def test_normalized_file_entries_must_not_collide(self):
        record = _candidate_record(OLD_KEY)
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [record],
                'app\\config.py': [_candidate_record(NEW_KEY)],
            },
        }
        with pytest.raises(InvalidBaselineError, match='normalize'):
            load_untrusted_baseline(candidate, SecretsCollection())

    def test_dot_segments_must_not_hide_a_collision(self):
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(OLD_KEY)],
                './app/config.py': [_candidate_record(NEW_KEY)],
            },
        }
        with pytest.raises(InvalidBaselineError, match='normalize'):
            load_untrusted_baseline(candidate, SecretsCollection())

    def test_duplicate_findings_are_rejected_not_deduped_by_order(self):
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [
                    _candidate_record(OLD_KEY, line_number=1),
                    _candidate_record(OLD_KEY, line_number=2),
                ],
            },
        }
        with pytest.raises(InvalidBaselineError, match='duplicat'):
            load_untrusted_baseline(candidate, SecretsCollection())

    def test_non_dict_input_is_rejected(self):
        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline([], SecretsCollection())  # type: ignore[arg-type]

    def test_non_collection_approved_input_is_rejected(self):
        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline(
                {'version': VERSION, 'results': {}},
                {},  # type: ignore[arg-type]
            )


class TestFailureAtomicityAndIsolation:
    @staticmethod
    def _approved_with_secret() -> SecretsCollection:
        approved = SecretsCollection()
        approved['app/config.py'].add(
            PotentialSecret('AWS Access Key', 'app/config.py', OLD_KEY, line_number=2),
        )
        return approved

    def test_bad_record_at_end_leaves_no_partial_result_and_inputs_intact(self):
        approved = self._approved_with_secret()
        approved_before = approved.json()
        candidate = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(OLD_KEY, line_number=2)],
                'app/evil.py': [{
                    'type': 'AWS Access Key',
                    'hashed_secret': 'not-valid-hex',
                    'line_number': 1,
                }],
            },
        }
        candidate_before = copy.deepcopy(candidate)

        with pytest.raises(InvalidBaselineError):
            load_untrusted_baseline(candidate, approved)

        assert candidate == candidate_before
        assert approved.json() == approved_before

    def test_consecutive_calls_are_isolated(self, tmp_path):
        approved = self._approved_with_secret()
        first = {
            'version': VERSION,
            'results': {'app/config.py': [_candidate_record(OLD_KEY, line_number=2)]},
        }
        second = {
            'version': VERSION,
            'results': {
                'app/config.py': [_candidate_record(NEW_KEY, line_number=2)],
            },
        }

        first_exemptions = load_untrusted_baseline(first, approved)
        second_exemptions = load_untrusted_baseline(second, approved)

        assert len(first_exemptions) == 1
        assert len(second_exemptions) == 0
        # The first result object is unaffected by the second invocation.
        assert len(first_exemptions) == 1
        assert len(approved) == 1

    def test_settings_and_plugin_filter_caches_are_untouched(self, tmp_path):
        with transient_settings({
            'plugins_used': [{'name': 'AWSKeyDetector'}],
        }):
            # Populate the lru_caches first.
            assert get_plugins()
            assert get_filters()
            settings_before = get_settings().json()
            plugin_cache_before = get_plugins.cache_info()
            filter_cache_before = get_filters.cache_info()

            evil_plugin = tmp_path / 'evil_plugin.py'
            evil_plugin.write_text(EVIL_PLUGIN)
            candidate = {
                'version': VERSION,
                'plugins_used': [{
                    'name': 'EvilDetector',
                    'path': f'file:///{evil_plugin}',
                }],
                'filters_used': [{
                    'path': f'file:///{evil_plugin}::should_exclude_secret',
                }],
                'results': {
                    'app/config.py': [_candidate_record(OLD_KEY)],
                },
            }

            load_untrusted_baseline(candidate, self._approved_with_secret())

            # Snapshot before any assertion that might itself touch the lru_caches
            # (Settings.json() calls get_plugins()).
            plugin_cache_after = get_plugins.cache_info()
            filter_cache_after = get_filters.cache_info()

            # No reconfiguration happened...
            assert get_settings().json() == settings_before
            # ...and the caches were neither cleared nor busted (cache_bust would reset
            # hits/misses/current-size to zero).
            assert plugin_cache_after == plugin_cache_before
            assert filter_cache_after == filter_cache_before
            assert not (tmp_path / 'evil_plugin.counter').exists()
