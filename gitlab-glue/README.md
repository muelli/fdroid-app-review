# gitlab-glue

The only part of this system allowed to talk to GitLab. Two adapters share one
interface (`gitlab_glue.base.GitLabAdapter`):

- `MockGitLab` (`gitlab_glue.mock`): fixture-driven, used everywhere by default
  (dev, tests, demo). Posted comments are written to an outbox directory instead of
  reaching any real project.
- `RealGitLab` (`gitlab_glue.real`): wraps `python-gitlab` against a live GitLab
  instance. Never imported by tests or default config. Requires explicit
  configuration (base URL, OAuth token, project path) that this repository does not
  ship, per the "no real-world side effects" constraint.

`gitlab_glue.apk_source` resolves where a given merge request's APK under test comes
from (direct artefact URL, F-Droid staging repo, or a local file), because public
documentation does not guarantee every fdroiddata MR pipeline publishes a durable
artefact URL (see `DECISIONS.md`).

`gitlab_glue.templates` renders the two Markdown outputs this system produces: the
evidence comment and the pre-filled review template. The templates themselves live
in `gitlab_glue/templates/*.md.tmpl` as plain Markdown with `$placeholders`.
