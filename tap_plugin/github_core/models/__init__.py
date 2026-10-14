"""GitHub Core plugin models package."""

from tap_plugin.github_core.models.actions_artifact import ActionsArtifact
from tap_plugin.github_core.models.actions_cache import ActionsCache
from tap_plugin.github_core.models.actions_secret import ActionsSecret
from tap_plugin.github_core.models.app_installation import AppInstallation
from tap_plugin.github_core.models.code_scanning_alert import CodeScanningAlert
from tap_plugin.github_core.models.code_scanning_analysis import CodeScanningAnalysis
from tap_plugin.github_core.models.collection_scope import CollectionScope
from tap_plugin.github_core.models.commit_observation import CommitObservation
from tap_plugin.github_core.models.dependabot_alert import DependabotAlert
from tap_plugin.github_core.models.github_account import GithubAccount
from tap_plugin.github_core.models.github_action import GithubAction
from tap_plugin.github_core.models.github_actions_job import GithubActionsJob
from tap_plugin.github_core.models.github_actions_run import GithubActionsRun
from tap_plugin.github_core.models.github_app import GithubApp
from tap_plugin.github_core.models.github_custom_property import GithubCustomProperty
from tap_plugin.github_core.models.github_environment import GithubEnvironment
from tap_plugin.github_core.models.github_package import GithubPackage
from tap_plugin.github_core.models.github_package_version import GithubPackageVersion
from tap_plugin.github_core.models.github_platform import GithubPlatform
from tap_plugin.github_core.models.github_release import GithubRelease
from tap_plugin.github_core.models.github_repository import GithubRepository
from tap_plugin.github_core.models.github_ruleset import GithubRuleset
from tap_plugin.github_core.models.github_runner import GithubRunner
from tap_plugin.github_core.models.github_workflow import GithubWorkflow
from tap_plugin.github_core.models.pull_request import PullRequest
from tap_plugin.github_core.models.rule_suite import RuleSuite
from tap_plugin.github_core.models.status_check import StatusCheck
from tap_plugin.github_core.models.workflow_job import WorkflowJob

__all__ = [
    "ActionsArtifact",
    "ActionsCache",
    "ActionsSecret",
    "CommitObservation",
    "AppInstallation",
    "CodeScanningAlert",
    "CodeScanningAnalysis",
    "CollectionScope",
    "DependabotAlert",
    "GithubAccount",
    "GithubAction",
    "GithubActionsJob",
    "GithubActionsRun",
    "GithubApp",
    "GithubCustomProperty",
    "GithubEnvironment",
    "GithubPackage",
    "GithubPackageVersion",
    "GithubPlatform",
    "GithubRelease",
    "GithubRepository",
    "GithubRuleset",
    "RuleSuite",
    "StatusCheck",
    "GithubRunner",
    "GithubWorkflow",
    "PullRequest",
    "WorkflowJob",
]
