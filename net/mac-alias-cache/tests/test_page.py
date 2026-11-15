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


def body():
    """ the page below its script block """
    return page().split("</script>", 1)[1]


def test_the_setting_is_cores_form_saved_then_applied():
    text = page()
    assert "{{ partial(\"layout_partials/base_form\", ['fields': generalForm, 'id': 'frm_general']) }}" in body()
    assert ("{{ partial('layout_partials/base_apply_button', "
            "{'data_endpoint': '/api/macaliascache/service/reconfigure'}) }}") in body()
    block = script()
    assert "mapDataToFormUI({'frm_general': '/api/macaliascache/settings/get'})" in block
    # Apply saves the form first and applies only a saved one, then shows the new state
    assert ("        $('#reconfigureAct').SimpleActionButton({\n"
            "            onPreAction: function () {\n"
            "                var dfObj = new $.Deferred();\n"
            "                saveFormToEndpoint('/api/macaliascache/settings/set', 'frm_general', "
            "function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });\n"
            "                return dfObj;\n"
            "            },\n"
            "            onAction: function (data) {\n"
            "                applied(data);\n"
            "                refresh();\n"
            "            }\n"
            "        });\n") in block
    assert text.count("/api/macaliascache/service/reconfigure") == 1


def test_the_neighbor_table_is_a_muted_line_and_never_a_banner_in_normal_operation():
    text = page()
    assert '<span id="neighbors" class="text-muted"' in body()
    block = script()
    assert ("        function neighborsText(data) {\n"
            "            var n = data.neighbors;\n"
            "            if (!n) return '';\n"
            "            if (!n.enabled) return \"{{ lang._('Neighbor table: off (the setting below turns it on)') "
            "}}\";\n"
            "            if (data.source === 'arp-ndp') return \"{{ lang._('Neighbor table: not used (host discovery "
            "is "
            "off)') }}\";\n"
            "            if (data.source !== 'discovery') return '';\n"
            "            return \"{{ lang._('Neighbor table: on,') }} \" + n.keys + ' ' + (n.keys === 1\n"
            "                ? \"{{ lang._('address added') }}\" : \"{{ lang._('addresses added') }}\");\n"
            "        }\n") in block
    assert "$('#neighbors').text(neighborsLine);" in block
    # emptied with the source line when the status itself failed
    head, _, tail = block.partition("var neighborsLine = '';")
    assert "neighborsLine = neighborsText(" not in head
    assert "neighborsLine" not in tail.split("} else {", 1)[0]
    for line in text.splitlines():
        if "banner(" in line:
            assert "Neighbor table: on" not in line and "Neighbor table: off" not in line


def test_a_neighbor_address_is_listed_as_such_and_never_as_cached_only():
    block = script()
    assert block.count("(cached only — removed by a flush)") == 1
    # the cached-only mark is given inside the loop over the MAC's own entry alone
    own = block.split("$.each(m.cache_items, function (k, ip) {", 1)[1].split("});", 1)[0]
    assert "(cached only — removed by a flush)" in own and "neighbor" not in own
    assert ("                        $.each(m.neighbor_items || [], function (k, item) {\n"
            "                            list.append($('<li/>').text(item.ip + ' ' + \"{{ lang._('(from the neighbor "
            "table)') }}\"));\n"
            "                        });\n") in block
    neighbor = block.split("$.each(m.neighbor_items || [], function (k, item) {", 1)[1].split("});", 1)[0]
    assert "text-danger" not in neighbor and "cached only" not in neighbor


def test_neighbor_only_problems_show_only_while_the_neighbor_table_is_in_use():
    # with the setting off or host discovery off there is nothing for the user to do about them. A settings
    # file that cannot be read reads as off, and is the one problem shown then
    block = script()
    assert ("var neighborItems = ['neighbor_merge', 'ndp', 'neighbors_setting', 'neighbors_file', "
            "'neighbors_lock'];") in block
    assert ("        function neighborsInUse(data) {\n"
            "            var n = data.neighbors || {};\n"
            "            return (n.enabled === true || n.setting === 'unusable') && data.source === 'discovery';\n"
            "        }\n") in block
    assert ("                $.each(data.problems || [], function (i, p) {\n"
            "                    if (neighborItems.indexOf(p.item) >= 0 && !inUse) return;\n"
            "                    banners.push(banner(p.blocks_flush ? 'danger' : 'warning', "
            "plain(p.problem || p.item)));\n"
            "                });\n") in block
    # the two conditions status computes are warnings on the same terms, and none blocks anything
    assert ("                if (inUse && data.neighbors.stale) {\n"
            "                    banners.push(banner('warning', \"{{ lang._(") in block
    assert ("                if (inUse && data.neighbors.over_limit > 0) {\n"
            "                    banners.push(banner('warning', \"{{ lang._(") in block
    assert "Addresses left out:') }} \" + data.neighbors.over_limit));" in block
    for line in block.splitlines():
        if "data.neighbors.stale" in line or "data.neighbors.over_limit" in line or "neighborItems.indexOf" in line:
            assert "danger" not in line


def test_the_page_names_the_neighbor_table_where_it_describes_what_a_flush_does():
    text = page()
    # the intro, the confirmation and the busy text
    assert "the IPv6 addresses the neighbor table has for a listed MAC and host discovery lacks" in body()
    assert ("{{ lang._('Rebuild all MAC aliases and the aliases nesting them from current host discovery data and the "
            "neighbor table? Addresses no longer reported will be removed from firewall rules.') }}") in text
    assert ("busy: \"{{ lang._('Another flush, an alias refresh or the neighbor table update is running. Try again in "
            "a "
            "moment.') }}\",") in text


def test_the_flush_result_says_when_the_neighbor_addresses_were_not_added():
    block = script()
    assert ("                if (data.neighbors && data.neighbors.skipped === 'neighbors_unavailable') {\n"
            "                    built.push(banner('warning', \"{{ lang._('The neighbor table could not be read, so "
            "its "
            "addresses were not added by this flush. The next minute adds them.') }}\"));\n"
            "                }\n") in block


FAILING_CODES = ("busy", "hosts_unavailable", "neighbors_unavailable", "cache_unreadable", "state_unusable",
                 "lock_unusable", "core_changed", "internal")


def test_a_tick_that_keeps_failing_is_a_warning_in_plain_words_while_the_setting_is_on():
    # status says so once a result other than ok has lasted ten minutes (neighbors.failing); the page has a
    # sentence for each result the tick can answer while the setting is on, and shows no code where it has one
    block = script()
    texts = block.split("var failingText = {", 1)[1].split("};", 1)[0]
    codes = re.findall(r"^\s+([a-z_]+): \"\{\{ lang\._\('", texts, re.MULTILINE)
    assert codes == list(FAILING_CODES) + ["cache_unsafe"]
    for line in texts.strip().splitlines():
        assert "The neighbor table update" in line and "changes nothing" in line
    assert texts.count("A flush writes the cache anew.") == 2
    assert "1 MiB" in texts
    # also with the setting off while keys remain: a removal that keeps failing leaves them for up to 12 hours
    assert ("                if (data.neighbors && data.neighbors.failing\n"
            "                        && (data.neighbors.enabled === true || data.neighbors.keys > 0)) {\n"
            "                    var failing = data.neighbors.failing;\n"
            "                    banners.push(banner('warning', (failingText[failingCode(data)]\n") in block
    assert "new Date(failing.since * 1000).toLocaleString()" in block
    for line in block.splitlines():
        if "failingText[" in line or "data.neighbors.failing" in line:
            assert "danger" not in line


def test_the_stale_warning_says_what_is_known():
    # a record that old says no run completed; why is not known (cron, a lock, the state directory)
    block = script()
    stale = block.split("if (inUse && data.neighbors.stale) {", 1)[1].split("}\n", 1)[0]
    assert "has not completed a run for over two hours" in stale
    assert "is not running" not in block


def test_apply_says_when_the_change_acts_within_a_minute():
    # reconfigure runs one tick so that the change acts now; when another update held the tick's or core's lock it
    # answered busy, and the next minute's tick makes the change
    block = script()
    assert ("        function applied(data) {\n"
            "            var busy = data && data.neighbors && data.neighbors.error === 'busy';\n"
            "            $('#apply-note').text(busy ? \"{{ lang._('The setting is saved. Another update was running, "
            "so "
            "the change acts within a minute.') }}\" : '').toggle(!!busy);\n"
            "        }\n") in block
    assert '<div class="alert alert-info" id="apply-note" style="display: none;"></div>' in body()


def test_the_page_says_the_setting_turns_the_neighbor_table_on():
    assert "With the setting below on and host discovery on, the plugin also adds" in body()


def test_the_cache_warning_says_whether_the_file_or_its_content_is_refused():
    # the result is one code; status lists the cache_file problem beside it when the file itself is refused
    block = script()
    assert ("        function failingCode(data) {\n"
            "            var code = data.neighbors.failing.result;\n"
            "            var unsafe = false;\n"
            "            $.each(data.problems || [], function (i, p) { if (p.item === 'cache_file') unsafe = true; "
            "});\n"
            "            return code === 'cache_unreadable' && unsafe ? 'cache_unsafe' : code;\n"
            "        }\n") in block
    texts = block.split("var failingText = {", 1)[1].split("};", 1)[0]
    lines = {line.split(":", 1)[0].strip(): line for line in texts.strip().splitlines()}
    assert "finds no JSON object in the MAC alias cache of core" in lines["cache_unreadable"]
    assert "is not a regular file of root with one link" in lines["cache_unsafe"]
