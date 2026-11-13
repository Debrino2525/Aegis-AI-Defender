"""Console markup must not turn API strings into HTML or inline script."""

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "static" / "index.html"


def esc(value) -> str:
    """Same replacements as the console esc() helper."""
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.append(dict(attrs))


def _parse(fragment: str) -> _Markup:
    parser = _Markup()
    parser.feed(fragment)
    return parser


def test_console_handlers_do_not_embed_api_strings():
    html = INDEX.read_text(encoding="utf-8")
    assert "function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}" in html

    forbidden = [
        "onclick=\"deleteMapping('${m.cidr_or_host}')\"",
        "onclick=\"deleteContact('${c.contact_id}')\"",
        "quickScanFromMonitor('${esc(t.host)}')",
        'value="${c.contact_id}"',
        "(${c.role} - ${c.phone})",
    ]
    for snippet in forbidden:
        assert snippet not in html, snippet

    assert 'data-host="${esc(t.host)}" onclick="quickScanFromMonitor(this.dataset.host)"' in html
    assert 'data-id="${esc(c.contact_id)}" onclick="deleteContact(this.dataset.id)"' in html
    assert 'data-cidr="${esc(m.cidr_or_host)}" onclick="deleteMapping(this.dataset.cidr)"' in html
    assert 'value="${esc(c.contact_id)}">${esc(c.name)} (${esc(c.role)} - ${esc(c.phone)})' in html


def test_malicious_contact_and_target_stay_text():
    contact_id = '"><img src=x onerror=alert(1)>'
    role = "<img src=x onerror=\"alert(1)\">"
    phone = "+233200000000"
    name = "Analyst"
    option = (
        f'<select><option value="{esc(contact_id)}">'
        f"{esc(name)} ({esc(role)} - {esc(phone)})</option></select>"
    )
    parsed = _parse(option)
    assert parsed.tags == ["select", "option"]
    assert parsed.attrs[1]["value"] == contact_id
    assert "<img" not in option

    host = "');alert(1);//"
    button = (
        f'<button data-host="{esc(host)}" '
        f'onclick="quickScanFromMonitor(this.dataset.host)">Scan</button>'
    )
    parsed = _parse(button)
    assert parsed.tags == ["button"]
    assert parsed.attrs[0]["onclick"] == "quickScanFromMonitor(this.dataset.host)"
    assert parsed.attrs[0]["data-host"] == host

    cidr = "10.0.0.0/8');alert(1)//"
    delete_btn = (
        f'<button data-cidr="{esc(cidr)}" '
        f'onclick="deleteMapping(this.dataset.cidr)"></button>'
    )
    parsed = _parse(delete_btn)
    assert parsed.attrs[0]["onclick"] == "deleteMapping(this.dataset.cidr)"
    assert parsed.attrs[0]["data-cidr"] == cidr
    assert "alert" not in parsed.attrs[0]["onclick"]
    print("[+] test_malicious_contact_and_target_stay_text: PASSED")


if __name__ == "__main__":
    test_console_handlers_do_not_embed_api_strings()
    print("[+] test_console_handlers_do_not_embed_api_strings: PASSED")
    test_malicious_contact_and_target_stay_text()
