"""Where a merge request's APK under test comes from.

Public documentation does not guarantee that every fdroiddata merge request
pipeline publishes a durable, downloadable APK artefact (see
`DECISIONS.md`, verify-first task 4). Rather than hard-code one assumption,
the APK source is pluggable: a broker deployment picks one strategy in
config, and can override it per merge request.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from pathlib import Path

from gitlab_glue.base import MergeRequestInfo


class ApkSource(abc.ABC):
    """Resolves a merge request to a path or URL the runtime can install."""

    @abc.abstractmethod
    def resolve(self, mr: MergeRequestInfo) -> str:
        """Return a local file path or an HTTP(S) URL to the APK."""


@dataclass(frozen=True, slots=True)
class ArtifactUrlSource(ApkSource):
    """A CI job artefact URL, when the fdroiddata pipeline for the MR publishes one.

    ``url_template`` is formatted with ``iid`` and ``package_name``, e.g.
    ``"https://gitlab.com/fdroid/fdroiddata/-/jobs/artifacts/{iid}/raw/{package_name}.apk"``.
    """

    url_template: str

    def resolve(self, mr: MergeRequestInfo) -> str:
        return self.url_template.format(iid=mr.iid, package_name=mr.package_name or "")


@dataclass(frozen=True, slots=True)
class StagingRepoSource(ApkSource):
    """An F-Droid staging/nightly repo index, keyed by package name."""

    repo_base_url: str

    def resolve(self, mr: MergeRequestInfo) -> str:
        if not mr.package_name:
            raise ValueError(f"MR !{mr.iid} has no package_name; cannot resolve staging repo APK")
        return f"{self.repo_base_url.rstrip('/')}/{mr.package_name}/latest.apk"


@dataclass(frozen=True, slots=True)
class LocalFileSource(ApkSource):
    """A file already sitting on the broker host. Used for demos and manual tests."""

    base_dir: Path
    filename_template: str = "{iid}.apk"

    def resolve(self, mr: MergeRequestInfo) -> str:
        path = self.base_dir / self.filename_template.format(
            iid=mr.iid, package_name=mr.package_name or ""
        )
        return str(path)
