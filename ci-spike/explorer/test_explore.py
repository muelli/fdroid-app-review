"""Offline tests for explore.py: parsing, blocker detection, choice of the next element, and the
loop itself against a fake device. Run: python3 -m pytest ci-spike/explorer"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import explore as ex  # noqa: E402

APP = "org.example.app"


def node(cls: str, pkg: str = APP, bounds: str = "[0,0][100,100]", **attrs: str) -> str:
    a = {
        "class": cls,
        "package": pkg,
        "bounds": bounds,
        "enabled": "true",
        "clickable": "false",
        "text": "",
        "content-desc": "",
        "resource-id": "",
        "password": "false",
    }
    a.update({k.replace("_", "-"): v for k, v in attrs.items()})
    return "<node " + " ".join(f'{k}="{v}"' for k, v in a.items()) + " />"


def dump(*nodes: str) -> str:
    return (
        "UI hierchary dumped to: /dev/tty\n<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>"
        '<hierarchy rotation="0"><node class="android.widget.FrameLayout" package="%s" '
        'bounds="[0,0][1080,2400]">%s</node></hierarchy>'
    ) % (APP, "".join(nodes))


def test_parse_keeps_only_clickable_and_editable_enabled_elements():
    s = ex.parse_dump(
        dump(
            node("android.widget.Button", text="Go", clickable="true", bounds="[10,20][110,120]"),
            node("android.widget.TextView", text="label"),
            node("android.widget.EditText", resource_id=f"{APP}:id/name"),
            node("android.widget.Button", text="off", clickable="true", enabled="false"),
            node("android.widget.Button", text="tiny", clickable="true", bounds="[0,0][2,2]"),
        )
    )
    assert [e.label for e in s.elements] == ["Go", "name"]
    assert s.elements[0].center == (60, 70)
    assert s.elements[1].editable


def test_parse_rejects_garbage():
    try:
        ex.parse_dump("ERROR: could not get idle state.")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_signature_ignores_text_so_typing_does_not_make_a_new_screen():
    a = ex.parse_dump(dump(node("android.widget.EditText", text="")))
    b = ex.parse_dump(dump(node("android.widget.EditText", text="test")))
    assert a.signature == b.signature


def test_blockers():
    login = ex.parse_dump(dump(node("android.widget.EditText", text="Password", password="true")))
    assert "login" in ex.blockers(login, APP)
    perm = ex.parse_dump(
        dump(
            node(
                "android.widget.Button",
                pkg="com.android.permissioncontroller",
                text="Allow",
                clickable="true",
            )
        )
    )
    assert "permission-dialog" in ex.blockers(perm, APP)
    web = ex.parse_dump(dump(node("android.webkit.WebView")))
    assert "webview" in ex.blockers(web, APP)
    qr = ex.parse_dump(
        dump(
            node("android.view.TextureView"),
            node("android.widget.Button", text="Scan QR code", clickable="true"),
        )
    )
    assert "camera-or-qr" in ex.blockers(qr, APP)
    assert "surface-view" in ex.blockers(qr, APP)
    canvas = ex.parse_dump(dump(node("android.view.SurfaceView")))
    assert "camera-or-qr" not in ex.blockers(canvas, APP)
    assert "no-accessible-elements" in ex.blockers(canvas, APP)


def test_choose_prefers_text_fields_then_reading_order_and_skips_dangerous_buttons():
    s = ex.parse_dump(
        dump(
            node(
                "android.widget.Button", text="Second", clickable="true", bounds="[0,500][100,600]"
            ),
            node(
                "android.widget.Button", text="Log out", clickable="true", bounds="[0,100][100,200]"
            ),
            node(
                "android.widget.Button", text="First", clickable="true", bounds="[0,300][100,400]"
            ),
            node("android.widget.EditText", bounds="[0,900][100,1000]"),
        )
    )
    tried: set[str] = set()
    order = []
    while (e := ex.choose(s, APP, tried)) is not None:
        tried.add(e.key)
        order.append(e.label)
    assert order == ["EditText", "First", "Second"]


def test_choose_allows_permission_dialog():
    s = ex.parse_dump(
        dump(
            node(
                "android.widget.Button",
                pkg="com.android.permissioncontroller",
                text="Don’t allow",
                clickable="true",
            ),
            node(
                "android.widget.Button",
                pkg="com.android.permissioncontroller",
                text="While using the app",
                clickable="true",
            ),
        )
    )
    assert ex.choose(s, APP, set()).text == "While using the app"


class FakeDevice:
    """Two screens: a home with a button that opens a detail screen; BACK returns home."""

    def __init__(self) -> None:
        self.screen = "home"
        self.calls: list[str] = []

    def __call__(self, argv: list[str], timeout: float) -> tuple[int, bytes]:
        cmd = " ".join(argv[1:])
        self.calls.append(cmd)
        if cmd.startswith("exec-out screencap"):
            return 0, b"\x89PNG fake"
        if "cat /sdcard/explore-ui.xml" in cmd:
            if self.screen == "home":
                return 0, dump(
                    node(
                        "android.widget.Button",
                        text="Open",
                        clickable="true",
                        bounds="[0,0][100,100]",
                    )
                ).encode()
            return 0, dump(
                node("android.widget.TextView", text="detail"),
                node(
                    "android.widget.Button",
                    text="Like",
                    clickable="true",
                    bounds="[0,200][100,300]",
                ),
            ).encode()
        if "input tap 50 50" in cmd:
            self.screen = "detail"
        if "KEYCODE_BACK" in cmd:
            self.screen = "home"
        if cmd == "shell logcat -d":
            return 0, f"I ActivityTaskManager: Displayed {APP}/.Main: +300ms\n".encode()
        if "dumpsys window" in cmd:
            return 0, f"mCurrentFocus=Window{{1 u0 {APP}/{APP}.Main}}".encode()
        return 0, b""


def test_explore_visits_both_screens_and_stops_when_nothing_is_left(tmp_path):
    dev = FakeDevice()
    s = ex.explore(ex.Adb("adb", runner=dev), APP, tmp_path, max_steps=20, pause=lambda _s: None)
    assert len(s.screens) == 2
    assert s.activities == [f"{APP}/{APP}.Main"]
    assert s.stopped_because.startswith("nothing new")
    steps = [json.loads(l) for l in (tmp_path / "steps.jsonl").read_text().splitlines()]
    assert [st["action"] for st in steps[:3]] == ["tap", "tap", "back"]
    assert (tmp_path / "screens" / "step-001.png").exists()


def test_crash_lines_only_for_the_app():
    log = (
        "E AndroidRuntime: FATAL EXCEPTION: main\nE AndroidRuntime: Process: other.app, PID: 1\n"
        "E AndroidRuntime: FATAL EXCEPTION: main\nE AndroidRuntime: Process: org.example.app, PID: 2\n"
    )
    assert len(ex.crash_lines(log, APP)) == 1


def test_compose_button_is_labelled_from_its_children_and_avoided_when_dangerous():
    xml = dump(
        '<node class="android.view.View" package="%s" bounds="[0,0][500,100]" enabled="true" '
        'clickable="true"><node class="android.widget.TextView" package="%s" text="Log out" '
        'bounds="[10,10][200,90]" enabled="true" clickable="false" /></node>' % (APP, APP),
        '<node class="android.view.View" package="%s" bounds="[0,200][500,300]" enabled="true" '
        'clickable="true"><node class="android.widget.TextView" package="%s" text="Settings" '
        'bounds="[10,210][200,290]" enabled="true" clickable="false" /></node>' % (APP, APP),
    )
    s = ex.parse_dump(xml)
    assert [e.label for e in s.elements] == ["Log out", "Settings"]
    assert ex.choose(s, APP, set()).label == "Settings"


def test_vpn_consent_dialog_is_answered():
    s = ex.parse_dump(dump(
        node("android.widget.Button", pkg="com.android.vpndialogs", text="Cancel", clickable="true"),
        node("android.widget.Button", pkg="com.android.vpndialogs", text="OK", clickable="true"),
    ))
    assert ex.choose(s, APP, set()).text == "OK"
