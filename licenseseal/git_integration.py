"""
LicenseSeal Git History Integration
===================================
Binds provenance signatures to specific Git commits for temporal verification.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class GitCommitInfo:
    """Git commit information for provenance binding."""
    commit_hash: str
    short_hash: str
    author: str
    author_email: str
    committed_at: str
    message: str
    repository_url: str
    branch: Optional[str] = None


class GitHistory:
    """Git history integration for temporal provenance."""

    def __init__(self, root: Path):
        self.root = root
        self._commit_info: Optional[GitCommitInfo] = None

    def get_current_commit(self) -> Optional[GitCommitInfo]:
        """Get current HEAD commit information."""
        if self._commit_info:
            return self._commit_info

        if not (self.root / ".git").exists():
            return None

        try:
            # Get commit hash
            hash_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            commit_hash = hash_result.stdout.strip()

            # Get short hash
            short_result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            short_hash = short_result.stdout.strip()

            # Get author info
            author_result = subprocess.run(
                ["git", "log", "-1", "--format=%an <%ae>"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            author = author_result.stdout.strip()

            # Get commit date
            date_result = subprocess.run(
                ["git", "log", "-1", "--format=%aI"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            committed_at = date_result.stdout.strip()

            # Get commit message
            msg_result = subprocess.run(
                ["git", "log", "-1", "--format=%s"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            message = msg_result.stdout.strip()

            # Get repository URL
            repo_url = self._get_remote_url()

            # Get current branch
            branch = self._get_current_branch()

            self._commit_info = GitCommitInfo(
                commit_hash=commit_hash,
                short_hash=short_hash,
                author=author,
                author_email=self._extract_email(author),
                committed_at=committed_at,
                message=message,
                repository_url=repo_url,
                branch=branch,
            )

            return self._commit_info

        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

    def _get_remote_url(self) -> str:
        """Get the remote origin URL."""
        try:
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            url = result.stdout.strip()
            # Normalize GitHub SSH URLs to HTTPS
            if url.startswith("git@github.com:"):
                url = "https://github.com/" + url[len("git@github.com:"):]
            return url
        except subprocess.CalledProcessError:
            return ""

    def _get_current_branch(self) -> Optional[str]:
        """Get the current branch name."""
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            branch = result.stdout.strip()
            return branch if branch else None
        except subprocess.CalledProcessError:
            return None

    def _extract_email(self, author_line: str) -> str:
        """Extract email from author line."""
        import re
        match = re.search(r"<(.+?)>", author_line)
        return match.group(1) if match else ""

    def verify_commit_exists(self, commit_hash: str) -> bool:
        """Verify that a commit hash exists in the local repository."""
        try:
            result = subprocess.run(
                ["git", "cat-file", "-t", commit_hash],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip() == "commit"
        except subprocess.CalledProcessError:
            return False

    def get_commit_history(self, max_count: int = 100) -> list[GitCommitInfo]:
        """Get recent commit history."""
        if not (self.root / ".git").exists():
            return []

        try:
            result = subprocess.run(
                [
                    "git", "log",
                    f"-{max_count}",
                    "--format=%H|%h|%an <%ae>|%aI|%s",
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )

            commits = []
            repo_url = self._get_remote_url()

            for line in result.stdout.strip().splitlines():
                if not line:
                    continue

                parts = line.split("|")
                if len(parts) >= 5:
                    commits.append(GitCommitInfo(
                        commit_hash=parts[0],
                        short_hash=parts[1],
                        author=parts[2],
                        author_email=self._extract_email(parts[2]),
                        committed_at=parts[3],
                        message=parts[4],
                        repository_url=repo_url,
                    ))

            return commits

        except (FileNotFoundError, subprocess.CalledProcessError):
            return []

    def get_file_history(self, file_path: Path) -> list[GitCommitInfo]:
        """Get commit history for a specific file."""
        if not (self.root / ".git").exists():
            return []

        rel_path = file_path.relative_to(self.root)

        try:
            result = subprocess.run(
                ["git", "log", "--format=%H|%h|%an <%ae>|%aI|%s", "--", str(rel_path)],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )

            commits = []
            repo_url = self._get_remote_url()

            for line in result.stdout.strip().splitlines():
                if not line:
                    continue

                parts = line.split("|")
                if len(parts) >= 5:
                    commits.append(GitCommitInfo(
                        commit_hash=parts[0],
                        short_hash=parts[1],
                        author=parts[2],
                        author_email=self._extract_email(parts[2]),
                        committed_at=parts[3],
                        message=parts[4],
                        repository_url=repo_url,
                    ))

            return commits

        except (FileNotFoundError, subprocess.CalledProcessError):
            return []


def get_git_info(root: Path) -> Optional[GitCommitInfo]:
    """Factory function to get Git commit info for a project."""
    git = GitHistory(root)
    return git.get_current_commit()


def verify_marker_commit(marker_commit_hash: str, root: Path) -> bool:
    """Verify that a commit hash from a marker exists in the repository."""
    git = GitHistory(root)
    return git.verify_commit_exists(marker_commit_hash)


def create_git_provenance_payload(
    root: Path,
    project: str,
    relative_path: str,
    license_id: str,
    owner: str,
    text_without_marker: str,
) -> dict:
    """
    Create a signature payload that includes Git commit information.
    """
    import hashlib
    import json

    git = GitHistory(root)
    commit_info = git.get_current_commit()

    # Calculate content digest
    content_hash = "sha256:" + hashlib.sha256(
        text_without_marker.encode("utf-8")
    ).hexdigest()

    payload = {
        "schema": "licenseseal.git-provenance.v1",
        "project": project,
        "relative_path": relative_path,
        "license": license_id,
        "owner": owner,
        "content_digest": content_hash,
    }

    # Add Git information if available
    if commit_info:
        payload["git_commit"] = commit_info.commit_hash
        payload["git_short_commit"] = commit_info.short_hash
        payload["git_repository_url"] = commit_info.repository_url
        payload["git_branch"] = commit_info.branch
        payload["git_committed_at"] = commit_info.committed_at

    return payload


def parse_git_fields_from_marker(marker_text: str) -> dict[str, str]:
    """Parse Git-related fields from a LicenseSeal marker."""
    import re

    fields = {}
    patterns = {
        "git_commit": r"^#?\s*GIT_COMMIT:\s*([a-f0-9]+)",
        "git_short_commit": r"^#?\s*GIT_SHORT_COMMIT:\s*([a-f0-9]+)",
        "git_repo": r"^#?\s*GIT_REPO:\s*(.+)",
        "git_branch": r"^#?\s*GIT_BRANCH:\s*(.+)",
        "git_committed_at": r"^#?\s*GIT_COMMITTED_AT:\s*(.+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, marker_text, re.MULTILINE)
        if match:
            fields[key] = match.group(1).strip()

    return fields


def format_git_marker_lines(
    comment: str,
    commit_info: GitCommitInfo,
) -> list[str]:
    """Format Git-related marker lines."""
    def c(text: str = "") -> str:
        return f"{comment} {text}".rstrip()

    return [
        c(f"GIT_COMMIT: {commit_info.commit_hash}"),
        c(f"GIT_SHORT_COMMIT: {commit_info.short_hash}"),
        c(f"GIT_REPO: {commit_info.repository_url}"),
        c(f"GIT_BRANCH: {commit_info.branch or '(detached)'}"),
        c(f"GIT_COMMITTED_AT: {commit_info.committed_at}"),
    ]


def get_repository_url(root: Path) -> str:
    """Get the remote repository URL."""
    git = GitHistory(root)
    commit_info = git.get_current_commit()
    return commit_info.repository_url if commit_info else ""


def get_commit_url(repo_url: str, commit_hash: str) -> str:
    """Convert a repository URL and commit hash to a web URL."""
    if not repo_url or not commit_hash:
        return ""

    # GitHub
    if "github.com" in repo_url:
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]
        return f"{repo_url}/commit/{commit_hash}"

    # GitLab
    if "gitlab.com" in repo_url:
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]
        return f"{repo_url}/-/commit/{commit_hash}"

    # Bitbucket
    if "bitbucket.org" in repo_url:
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]
        return f"{repo_url}/commits/{commit_hash}"

    return ""