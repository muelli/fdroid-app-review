from pathlib import Path

from netpolicy.config import PolicyConfig
from netpolicy.rules import generate_apply_script, generate_remove_script, generate_ruleset

GOLDEN = Path(__file__).parent / "golden"


def _config() -> PolicyConfig:
    return PolicyConfig(
        session_id="abc123deadbeef",
        netns_name="fdroid-sess-abc123deadbeef",
        deny_host_ranges=("203.0.113.0/24",),
    )


def test_ruleset_matches_golden() -> None:
    assert generate_ruleset(_config()) == (GOLDEN / "basic.nft").read_text()


def test_apply_script_matches_golden() -> None:
    assert generate_apply_script(_config()) == (GOLDEN / "basic-apply.sh").read_text()


def test_remove_script_matches_golden() -> None:
    assert generate_remove_script(_config()) == (GOLDEN / "basic-remove.sh").read_text()


def test_ruleset_omits_optional_sections_when_disabled() -> None:
    config = PolicyConfig(
        session_id="minimal",
        netns_name="fdroid-sess-minimal",
        deny_rfc1918=False,
        deny_link_local=False,
        deny_host_ranges=(),
        deny_tcp_ports=(),
    )
    ruleset = generate_ruleset(config)
    assert "RFC1918" not in ruleset
    assert "link-local" not in ruleset
    assert "configured host ranges" not in ruleset
    assert "configured TCP ports" not in ruleset
    assert "packet rate cap" in ruleset


def test_table_name_is_session_scoped() -> None:
    config = _config()
    assert config.table_name in generate_ruleset(config)
    assert config.table_name in generate_remove_script(config)
