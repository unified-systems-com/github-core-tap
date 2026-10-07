"""The 0022 backfill: existing code_scanning_alert rows get repository_github_id
populated from their repository, without guessing when that's ambiguous.

AI review on PR#212 (github-core-tap) caught that the migration added the column
with no backfill — an in-place (non-wipe) deployment would leave every existing
alert at NULL while new collection runs supply a real id, duplicating instead of
adopting. This proves the backfill function closes exactly that gap, and that it
backs off rather than guesses when a full_name matches more than one live repo
(a pre-#209 rename duplicate) or no repo at all.
"""

from __future__ import annotations

import importlib

import pytest
from django.apps import apps

migration_module = importlib.import_module(
    "tap_plugin.github_core.migrations"
    ".0022_remove_actionsartifact_nk_github_core__action_5b40a61_and_more"
)


@pytest.mark.django_db
class TestBackfillRepositoryGithubId:
    def test_a_null_alert_adopts_its_single_matching_repos_id(self) -> None:
        from tap_grid.write_guard import unguarded_write

        GithubRepository = apps.get_model("github_core", "GithubRepository")
        CodeScanningAlert = apps.get_model("github_core", "CodeScanningAlert")

        with unguarded_write():
            repo = GithubRepository.objects.create(
                full_name="unified-systems-com/one-repo", github_id=111
            )
            alert = CodeScanningAlert.objects.create(
                full_name="unified-systems-com/one-repo",
                number=1,
                repository_github_id=None,
            )

        migration_module.backfill_repository_github_id(apps, None)

        alert.refresh_from_db()
        assert alert.repository_github_id == repo.github_id

    def test_an_ambiguous_full_name_is_left_null_not_guessed(self) -> None:
        """Two live repos sharing a full_name is exactly the pre-#209 rename-duplicate
        shape; picking either would be a guess, so this must back off."""
        from tap_grid.write_guard import unguarded_write

        GithubRepository = apps.get_model("github_core", "GithubRepository")
        CodeScanningAlert = apps.get_model("github_core", "CodeScanningAlert")

        with unguarded_write():
            GithubRepository.objects.create(full_name="unified-systems-com/dupe", github_id=222)
            GithubRepository.objects.create(full_name="unified-systems-com/dupe", github_id=333)
            alert = CodeScanningAlert.objects.create(
                full_name="unified-systems-com/dupe",
                number=1,
                repository_github_id=None,
            )

        migration_module.backfill_repository_github_id(apps, None)

        alert.refresh_from_db()
        assert alert.repository_github_id is None

    def test_no_matching_repo_is_left_null(self) -> None:
        from tap_grid.write_guard import unguarded_write

        CodeScanningAlert = apps.get_model("github_core", "CodeScanningAlert")

        with unguarded_write():
            alert = CodeScanningAlert.objects.create(
                full_name="unified-systems-com/ghost-repo",
                number=1,
                repository_github_id=None,
            )

        migration_module.backfill_repository_github_id(apps, None)

        alert.refresh_from_db()
        assert alert.repository_github_id is None

    def test_an_already_populated_alert_is_left_alone(self) -> None:
        """The backfill only targets NULL rows — never re-derives an id that
        collection already supplied, even if a repo rename makes a full_name
        join resolve to something different now."""
        from tap_grid.write_guard import unguarded_write

        GithubRepository = apps.get_model("github_core", "GithubRepository")
        CodeScanningAlert = apps.get_model("github_core", "CodeScanningAlert")

        with unguarded_write():
            GithubRepository.objects.create(
                full_name="unified-systems-com/already-set", github_id=444
            )
            alert = CodeScanningAlert.objects.create(
                full_name="unified-systems-com/already-set",
                number=1,
                repository_github_id=999,
            )

        migration_module.backfill_repository_github_id(apps, None)

        alert.refresh_from_db()
        assert alert.repository_github_id == 999
