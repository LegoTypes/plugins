import os
import re

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
    assert "if (n.shown) {\n                        banners.push(banner('info', plain(n.note)));" in text


def test_the_null_source_warning_stays_and_the_source_line_is_emptied_on_error():
    text = page()
    assert "banner('warning', \"{{ lang._('The host list could not be read;" in text
    assert "var sourceLine = '';" in text
    assert "$('#source').text(sourceLine);" in text
    head, _, tail = text.partition("var sourceLine = '';")
    assert "sourceLine = sourceText(" not in head
    error_branch = tail.split("} else {", 1)[0]
    assert "sourceLine" not in error_branch


def test_the_flush_result_warns_for_each_way_cores_update_went_wrong():
    # the exit status first; only an exit status of 0 has a reply, whose status is then none, error or ok. With no
    # status the page shows what core did print, when it printed anything
    text = page()
    assert "                var update = data.update_tables;\n                if (update) {\n" in text
    assert ("                    if (update.rc !== 0) {\n"
            "                        built.push(banner('warning', \"{{ lang._('update_tables.py reported a "
            "problem:') }} \" + output));\n"
            "                    } else if (update.status === null || update.status === undefined) {\n"
            "                        built.push(banner('warning', \"{{ lang._('The update by core printed no reply the "
            "plugin could read') }}\" + (output ? ': ' + output : '.')));\n"
            "                    } else if (update.status === 'error') {\n"
            "                        built.push(banner('warning', \"{{ lang._('Core reported an error loading an alias "
            "table:') }} \" + messages));\n"
            "                    } else if (update.status !== 'ok') {\n"
            "                        built.push(banner('warning', \"{{ lang._('The update by core answered with the "
            "status') }} \" + plain(update.status) + (messages ? ': ' + messages : '')));\n"
            "                    }\n") in text


def test_the_flush_result_says_when_emptied_tables_kept_their_addresses():
    # the sentence states the outcome alone, which holds however the update failed to answer
    text = page()
    assert ("                    if (!update.complete) {\n"
            "                        built.push(banner('warning', \"{{ lang._('A table this update left empty was not "
            "flushed and keeps its addresses until the next flush.') }}\"));\n"
            "                    }\n") in text


def test_the_flush_result_marks_each_alias_core_never_rebuilds():
    text = page()
    assert "built.push(summaryTable(data.summary, data.no_expiry || []));" in text
    assert "summaryTable(data.last_flush.summary, [])" in text
    assert ("                if (noExpiry.indexOf(s.name) >= 0) {\n"
            "                    name.append($('<div class=\"text-warning\"/>').text(\"{{ lang._('not rebuilt: its "
            "lifetime is not above 0') }}\"));\n") in text


def script():
    """ the page's script block, where every translated string is a JavaScript string literal """
    return page().split("<script>", 1)[1].split("</script>", 1)[0]


def test_no_translated_string_of_the_script_holds_a_character_core_escapes():
    # core's lang._() returns htmlspecialchars(text, ENT_QUOTES), and the page sets its strings with .text(), which
    # shows an entity as it is written: a string with one of these characters would show &#039;, &quot;, &lt;,
    # &gt; or &amp;
    block = script()
    strings = [m.group(2) for m in re.finditer(r"""\{\{ lang\._\((['"])(.*?)\1\) \}\}""", block)]
    assert len(strings) == block.count("{{") == block.count("lang._(") > 40
    assert [s for s in strings if re.search(r"""['"<>&]""", s)] == []


def test_server_text_is_decoded_before_it_is_set_as_text():
    # core's API encodes a reply with htmlspecialchars(..., ENT_NOQUOTES); plain() is its exact inverse, the same
    # function the sibling plugins' pages have
    block = script()
    assert ("        function plain(s) {\n"
            "            return String(s === undefined || s === null ? '' : s).replace(/&lt;/g, '<')"
            ".replace(/&gt;/g, '>').replace(/&amp;/g, '&');\n"
            "        }\n") in block
    for use in (
        "(map[data.error] || (plain(data.error) + ':')) + (data.detail ? ' ' + plain(data.detail) : '')",
        "\"{{ lang._('Host list:') }} \" + plain(source)",
        "banner(p.blocks_flush ? 'danger' : 'warning', plain(p.problem || p.item))",
        "banner('info', plain(n.note))",
        ".text(plain(data.errorMessage))",
        ".text(plain(data.note))",
        "var output = plain(update.output);",
        "var messages = plain((update.messages || []).join('; '));",
        "plain(update.status)",
    ):
        assert use in block, use
    # none of them reaches the page undecoded
    for bare in ("+ data.detail", "+ source;", "'warning', p.problem", "'info', n.note)", ".text(data.errorMessage)",
                 ".text(data.note)", "+ update.output", "+ update.status", "+ update.messages"):
        assert bare not in block, bare
