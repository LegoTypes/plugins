import os

VOLT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "opnsense", "mvc", "app", "views", "OPNsense", "MacAliasCache", "index.volt",
)


def page():
    with open(VOLT, encoding="utf-8") as fh:
        return fh.read()


def test_the_host_list_source_is_never_a_banner():
    text = page()
    for line in text.splitlines():
        if "banner(" in line:
            assert "arp-ndp" not in line
            assert "hostwatch" not in line
    assert '<span id="source" class="text-muted"' in text
    assert "lang._('Host list: host discovery')" in text
    assert "lang._('Host list: ARP and NDP tables (host discovery is off)')" in text


def test_notes_render_as_information():
    text = page()
    assert "data.notes" in text
    assert "banner('info', n.note)" in text


def test_the_null_source_warning_stays_and_the_source_line_is_emptied_on_error():
    text = page()
    assert "banner('warning', \"{{ lang._('The host list could not be read;" in text
    assert "var sourceLine = '';" in text
    assert "$('#source').text(sourceLine);" in text
    head, _, tail = text.partition("var sourceLine = '';")
    assert "sourceLine = sourceText(" not in head
    error_branch = tail.split("} else {", 1)[0]
    assert "sourceLine" not in error_branch
