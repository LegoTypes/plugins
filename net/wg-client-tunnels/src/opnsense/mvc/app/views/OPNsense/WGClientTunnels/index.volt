{#
 # Copyright (C) 2026 cayossarian (Bill Flood)
 # All rights reserved.
 # BSD 2-Clause License
 #}

<style>
    a.wgct-link { color: inherit; text-decoration: none; border-bottom: 1px dotted currentColor; }
    a.wgct-link:hover { text-decoration: none; border-bottom-style: solid; }
    .wgct-result pre { white-space: pre-wrap; }
</style>

<script>
    $(document).ready(function () {
        var links = {
            instance: '/ui/wireguard/general#instances',
            peers: '/ui/wireguard/general#peers',
            assignments: '/ui/interfaces/assignment',
            iface: '/interfaces.php?if=',
            gateways: '/ui/routing/configuration',
            routes: '/ui/routes',
            nat: '/ui/firewall/source_nat',
            groups: '/ui/routing/gateway_groups'
        };
        var failedText = "{{ lang._('The request failed (session expired or the web server is restarting). Reload the page and try again.') }}";
        var options = null;

        /* core HTML-escapes every API reply string (Mvc/Response.php, htmlspecialchars ENT_NOQUOTES), so a
         * server string with '>' or '&' (a peer name, a finding detail, a sentinel description) arrives as
         * '...&gt;...'. Decode it once here; the result only ever reaches .text()/.attr('title'), which never
         * interpret it as HTML, so decoding cannot introduce markup (review finding 2). */
        function plain(s) {
            return $('<textarea/>').html(s === undefined || s === null ? '' : String(s)).val();
        }

        /* a dialog title that may include a server-supplied name: a text node, never an HTML string --
         * BootstrapDialog renders a string title as HTML, which would re-encode plain()'s output (review
         * finding 5). Callers pass the already-decoded text. */
        function titleText(text) {
            return $('<span/>').text(text);
        }

        function link(text, href) {
            return $('<a/>').addClass('wgct-link').attr('href', href).text(plain(text));
        }

        function dash() {
            return $('<span/>').text('—');
        }

        /* the grid's cells (core UIBootgrid formatters, (column, row) signature). Each returns a DOM node
         * built with .text()/.attr(), never an HTML string, so no config-derived value (a tunnel, interface
         * or gateway name, a finding text) is ever parsed as markup. Row values arrive entity-encoded like
         * every API reply and pass through plain() exactly once: inside link(), or right before .text() or
         * .attr(). */
        function gwNode(name, status, statusText, held) {
            if (!name) {
                return dash()[0];
            }
            var cell = $('<div/>').append(link(name, links.gateways));
            if (held) {
                cell.append(' ', $('<span class="label label-info"/>').text("{{ lang._('held by mirror') }}"));
            }
            return cell[0];
        }

        /* a gateway's status as core's gateway page shows it: a coloured plug with the status as its tooltip.
         * labelClass comes from wgct_gateway_label_class() (a fixed set of classes); anything else is ignored */
        function statusNode(labelClass, statusText) {
            if (!/^fa fa-plug text-(success|warning|danger|default)$/.test(labelClass || '')) {
                return dash()[0];
            }
            return $('<i class="bootgrid-tooltip" data-toggle="tooltip"/>')
                .addClass(labelClass)
                .attr('title', plain(statusText || "{{ lang._('Pending') }}"))[0];
        }

        function linkOrDash(text, href) {
            return (text ? link(text, href) : dash())[0];
        }

        var gridFormatters = {
            tunnel: function (column, t) {
                var cell = $('<div/>').append(link(t.name, links.instance));
                if (t.device) {
                    var ifaceLabel = t.interface_descr || t.interface;
                    cell.append($('<br/>'), $('<small class="text-muted"/>').append(t.interface
                        ? link(t.device + (ifaceLabel ? ' / ' + ifaceLabel : ''), links.iface + encodeURIComponent(plain(t.interface)))
                        : link(t.device + ' — ' + "{{ lang._('not assigned') }}", links.assignments)));
                }
                if (t.enabled !== '1') {
                    cell.append(' ', $('<span class="label label-default"/>').text("{{ lang._('disabled') }}"));
                }
                return cell[0];
            },
            endpoint: function (column, t) { return linkOrDash(t.endpoint, links.peers); },
            boundwan: function (column, t) { return linkOrDash(t.bound_wan, links.routes); },
            mtu: function (column, t) {
                var cell = $('<div/>').text(t.mtu);
                if (t.clamp_text) {
                    cell.append($('<br/>'), $('<small class="text-muted"/>').text(plain(t.clamp_text)));
                }
                return cell[0];
            },
            gw4: function (column, t) { return gwNode(t.gw4, t.gw4_status, t.gw4_status_text, t.held); },
            gw6: function (column, t) { return gwNode(t.gw6, t.gw6_status, t.gw6_status_text, false); },
            status4: function (column, t) { return statusNode(t.gw4_label_class, t.gw4_status_text); },
            status6: function (column, t) { return statusNode(t.gw6_label_class, t.gw6_status_text); },
            nat: function (column, t) { return linkOrDash(t.nat_text, links.nat); },
            groups: function (column, t) { return linkOrDash(t.groups_text, links.groups); },
            /* bootgrid-tooltip: the grid gives each badge core's tooltip, which shows the title as text */
            findings: function (column, t) {
                if (!t.findings.length) {
                    return dash()[0];
                }
                var cell = $('<div/>');
                $.each(t.findings, function (i, f) {
                    cell.append($('<span class="label bootgrid-tooltip" style="display:inline-block; margin:1px;"/>')
                        .addClass(f.blocking ? 'label-danger' : 'label-warning')
                        .attr('title', plain(f.detail) + ' — ' + plain(f.fix))
                        .text(plain(f.code)), ' ');
                });
                return cell[0];
            }
        };

        /* ---- action results ---- */

        /* status is jQuery's: 'success' only for a completed request whose reply parsed as JSON. An error
         * page, a timeout or a login redirect reaches the callback as a jqXHR without any of our keys,
         * and must never read as "Nothing to change" (review I4). Every action's result shares the same
         * {ok, saved, errors, ...} shape (actions.php wgct_result()); ok:false with no error lines (an
         * apply step failed with only 'apply' detail, nothing in 'errors') must still read as a failure,
         * never as success or "Nothing to change" (review finding 1). */
        function errorList(r, status) {
            if (!r || (status !== undefined && status !== 'success')
                || !('ok' in r || 'result' in r || 'status' in r || 'errors' in r)) {
                return [r && r.errorMessage ? plain(r.errorMessage) : failedText];
            }
            var out = [];
            $.each(r.errors || [], function (k, m) { out.push(plain(m)); });
            if (out.length === 0 && (r.ok === false
                || (r.result === 'failed' && $.isEmptyObject(r.validations || {})))) {
                out.push(failedText);
            }
            return out;
        }

        function resultLines(r) {
            var lines = [];
            $.each((r && r.changes) || [], function (i, c) { lines.push(plain(c)); });
            $.each((r && r.apply) || [], function (i, s) { lines.push('configctl ' + plain(s.action) + ': ' + plain(s.result)); });
            if (r && r.after && r.after.reconcile) {
                lines.push("{{ lang._('alarm replayed for') }}: " + (r.after.replayed.length ? $.map(r.after.replayed, plain).join(', ') : '—'));
                lines.push("{{ lang._('reconcile') }}: " + plain(r.after.reconcile));
            }
            return lines;
        }

        function resultBody(r, status) {
            var body = $('<div class="wgct-result"/>');
            var errors = errorList(r, status);
            $.each(errors, function (i, m) { body.append($('<div class="alert alert-danger"/>').text(m)); });
            var lines = errors.length && !(r && 'changes' in r) ? [] : resultLines(r);
            if (lines.length) {
                body.append($('<pre/>').text(lines.join('\n')));
            } else if (!errors.length) {
                body.append($('<p/>').text("{{ lang._('Nothing to change.') }}"));
            }
            return body;
        }

        function runApply(uuid, name) {
            ajaxCall('/api/wgclienttunnels/tunnels/apply/' + uuid, {}, function (r, status) {
                refreshAll();
                showResult(titleText("{{ lang._('Apply') }} " + plain(name)), r, status, uuid, name);
            });
        }

        /* applyUuid/applyName: the uuid and name of a tunnel that is saved (Create, or an earlier Apply); when
         * its apply did not complete, the dialog offers "Apply again" (ruling 20) -- the finding apply-pending
         * stays until one completes. applyName is the tunnel's own name, never the dialog title (review
         * finding 4: a title like "Rebind NAME" must not become the next dialog's "Apply Rebind NAME"). */
        function showResult(title, r, status, applyUuid, applyName) {
            var failed = errorList(r, status).length > 0;
            var buttons = [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}];
            if (failed && applyUuid) {
                buttons.unshift({
                    label: "{{ lang._('Apply again') }}",
                    cssClass: 'btn-primary',
                    action: function (d) { d.close(); runApply(applyUuid, applyName); }
                });
            }
            var body = resultBody(r, status);
            if (r && r.saved === true && r.ok === false) {
                /* the config write happened even though the apply step after it did not finish -- never let
                 * that read as a lost change (review finding 1). The wording follows what the dialog actually
                 * offers: only Create/Apply's own retry uses the generic apply endpoint (ruling 21); Rebind's
                 * own apply ("interface routes configure", then "wireguard restart") is not the same pipeline, so its
                 * failure gets a plainer message instead of a misleading "Apply again". */
                body.prepend($('<div class="alert alert-warning"/>').text(applyUuid
                    ? "{{ lang._('Saved; the apply did not complete. Apply again, or use the Apply button in the tunnel row.') }}"
                    : "{{ lang._('Saved; the follow-up step above did not complete. Check the list and the system log.') }}"
                ));
            }
            /* the caller has already reloaded the lists when the reply arrived: they are current behind
             * this dialog, not only once it is closed */
            BootstrapDialog.show({
                type: failed ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_INFO,
                title: title,
                message: body,
                buttons: buttons
            });
        }

        /* preview with dry=1 first: the confirmation lists exactly what will change, or why it cannot */
        function confirmAction(title, url, yesLabel) {
            ajaxCall(url, {dry: '1'}, function (preview, previewStatus) {
                var refused = errorList(preview, previewStatus).length > 0;
                var nothing = !refused && resultLines(preview).length === 0;
                var buttons = [{label: "{{ lang._('Cancel') }}", action: function (d) { d.close(); }}];
                if (!refused && !nothing) {
                    buttons.push({
                        label: yesLabel,
                        cssClass: 'btn-primary',
                        action: function (d) {
                            d.close();
                            ajaxCall(url, {}, function (r, status) {
                                refreshAll();
                                showResult(title, r, status);
                            });
                        }
                    });
                }
                BootstrapDialog.show({
                    type: refused ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_WARNING,
                    title: title,
                    message: resultBody(preview, previewStatus),
                    buttons: buttons
                });
            });
        }

        /* ---- dialogs ---- */

        function loadOptions(done) {
            /* POST like the lists: the choices (templates, stale routes) change with every action */
            ajaxCall('/api/wgclienttunnels/tunnels/options', {}, function (data, status) {
                if (!data || status !== 'success' || data.status !== 'ok') {
                    showResult("{{ lang._('Client tunnels') }}", null, status);
                    return;
                }
                options = data;
                done();
            });
        }

        function fillSelect(selector, items, selected) {
            var select = $(selector).empty();
            $.each(items, function (i, it) {
                select.append($('<option/>').val(it.value).text(plain(it.label)).prop('selected', selected.indexOf(it.value) !== -1));
            });
            select.selectpicker('refresh');
        }

        /* the public parts of a wg-quick config, read in the browser; the private key is never touched */
        function wgPublic(text) {
            var section = '';
            var endpoint = null;
            var v6 = [];
            $.each((text || '').split(/\r?\n/), function (i, raw) {
                var line = raw.split('#')[0].trim();
                if (line === '') {
                    return;
                }
                if (line.charAt(0) === '[') {
                    section = line.toLowerCase();
                    return;
                }
                var eq = line.indexOf('=');
                if (eq < 0) {
                    return;
                }
                var key = line.slice(0, eq).trim().toLowerCase();
                var value = line.slice(eq + 1).trim();
                if (section === '[peer]' && key === 'endpoint') {
                    endpoint = value;
                } else if (section === '[interface]' && key === 'address') {
                    $.each(value.split(','), function (j, a) {
                        a = a.trim();
                        if (a.indexOf(':') !== -1) {
                            v6.push(a.split('/')[0]);
                        }
                    });
                }
            });
            var m = endpoint ? endpoint.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/) : null;
            return {endpoint_ip: m ? m[1] : null, v6: v6};
        }

        /* an IPv6 address in one comparable form: 8 groups, lower case, no leading zeros */
        function expand6(address) {
            var a = String(address || '').toLowerCase().split('%')[0];
            var halves = a.split('::');
            if (halves.length > 2) {
                return a;
            }
            var head = halves[0] ? halves[0].split(':') : [];
            var tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
            var groups = head.slice();
            for (var i = 0; halves.length === 2 && i < 8 - head.length - tail.length; i++) {
                groups.push('0');
            }
            groups = groups.concat(tail);
            return $.map(groups, function (g) { return (parseInt(g, 16) || 0).toString(16); }).join(':');
        }

        /* the last parsed IPv6 address list (sorted, comma-joined); ipv6Defaults only recomputes the
         * checkbox defaults when this actually changes, so an explicit uncheck/check survives further
         * edits elsewhere in the pasted config (review finding 7). Reset to null whenever the dialog opens
         * on a blank config, so the next paste always recomputes regardless of a coincidental match with a
         * previous session's list. */
        var lastV6 = null;

        /* rulings 3 and 4: IPv6 only when the config has an address; unique addressing on by default when that
         * address is already on a WireGuard instance or the managed tunnels use fd00::N:1. A missed match only
         * leaves the box unchecked, and the planner then refuses the duplicate explicitly. */
        function ipv6Defaults() {
            if (!options) {
                return;
            }
            var p = wgPublic($('#create\\.config').val());
            var key = p.v6.slice().sort().join(',');
            if (key === lastV6) {
                return;
            }
            lastV6 = key;
            var hasV6 = p.v6.length > 0;
            $('#create\\.ipv6').prop('disabled', !hasV6).prop('checked', hasV6);
            var known = $.map(options.instance_ipv6, expand6);
            var shared = false;
            $.each(p.v6, function (i, a) {
                if (known.indexOf(expand6(a)) !== -1) {
                    shared = true;
                }
            });
            $('#create\\.unique').prop('checked', hasV6 && (options.unique_convention || shared));
            natRows();
        }

        function natRows() {
            var template = $('#create\\.template').val() !== '';
            var ipv6 = $('#create\\.ipv6').prop('checked');
            $('#row_create\\.nat4').toggle(!template);
            $('#row_create\\.nat6').toggle(!template && ipv6);
            $('#row_create\\.unique').toggle(ipv6);
        }

        /* the keyless MTU probe (measure_mtu) for Create's and Edit's MTU fields */
        function measureMtu(endpoint, wan, mtuInput, why, button) {
            if (!endpoint || !wan) {
                why.text("{{ lang._('Choose the WAN, and paste a config with an IPv4 endpoint for a new server, first.') }}");
                return;
            }
            button.prop('disabled', true);
            why.text("{{ lang._('Measuring the path; this takes up to half a minute...') }}");
            ajaxCall('/api/wgclienttunnels/tunnels/measure_mtu', {wan: wan, endpoint: endpoint}, function (r, status) {
                button.prop('disabled', false);
                if (status === 'success' && r && r.ok) {
                    mtuInput.val(r.mtu);
                    why.text(plain(r.why));
                } else {
                    why.text(errorList(r, status).join('; '));
                }
            });
        }

        function measure() {
            measureMtu(wgPublic($('#create\\.config').val()).endpoint_ip, $('#create\\.wan').val(),
                $('#create\\.mtu'), $('#wgct-mtu-why'), $('#wgct-measure'));
        }

        /* "Load file": the browser reads the file into the textbox; nothing is uploaded */
        function fileLoader(button, input, target) {
            button.on('click', function () { input.click(); });
            input.on('change', function () {
                var file = this.files && this.files[0];
                if (!file) {
                    return;
                }
                var reader = new FileReader();
                reader.onload = function () {
                    target.val(reader.result).trigger('input');
                    input.val('');
                };
                reader.readAsText(file);
            });
        }

        function openCreate() {
            loadOptions(function () {
                lastV6 = null;
                $('#create\\.config, #create\\.name, #create\\.monitor, #create\\.mtu').val('');
                $('#create\\.ipv6').prop('checked', false).prop('disabled', true);
                $('#create\\.unique').prop('checked', false);
                fillSelect('#create\\.wan', options.wans, options.wans.length ? [options.wans[0].value] : []);
                fillSelect('#create\\.template', [{value: '', label: "{{ lang._('(none: choose NAT sources)') }}"}].concat(options.templates),
                    options.templates.length ? [options.templates[0].value] : ['']);
                fillSelect('#create\\.nat4', options.nat_sources, []);
                fillSelect('#create\\.nat6', options.nat_sources, []);
                $('#wgct-mtu-why').text('');
                $('#wgct-create-errors').empty();
                handleFormValidation('frm_dialogCreate', {});
                natRows();
                $('#dialogCreate').modal('show');
            });
        }

        function submitCreate() {
            var data = getFormData('frm_dialogCreate');
            var c = data.create;
            var run = function () {
                $('#btn_dialogCreate_save').prop('disabled', true);
                $('#btn_dialogCreate_save_progress').addClass('fa fa-spinner fa-pulse');
                ajaxCall('/api/wgclienttunnels/tunnels/create', data, function (r, status) {
                    $('#btn_dialogCreate_save').prop('disabled', false);
                    $('#btn_dialogCreate_save_progress').removeClass('fa fa-spinner fa-pulse');
                    /* every reply, a refusal included: a failure after the save still leaves a tunnel to show */
                    refreshAll();
                    if (status === 'success' && r && r.result === 'saved') {
                        $('#dialogCreate').modal('hide');
                        /* applyName is the submitted name, never the dialog title (review finding 4) */
                        showResult("{{ lang._('Create tunnel') }}", r, status, r.uuid, c.name);
                        return;
                    }
                    handleFormValidation('frm_dialogCreate', (status === 'success' && r && r.validations) || {});
                    var box = $('#wgct-create-errors').empty();
                    $.each(errorList(r, status), function (i, m) { box.append($('<div class="alert alert-danger"/>').text(m)); });
                    if (status !== 'success') {
                        /* the request died after the save, perhaps: the list shows apply-pending and an Apply button then */
                        box.append($('<div class="alert alert-warning"/>').text("{{ lang._('If the tunnel appears in the list with the finding apply-pending, it was saved: press its Apply button.') }}"));
                    }
                });
            };
            var missing = [];
            if (c.template === '' && c.nat4 === '') {
                missing.push('IPv4');
            }
            if (c.template === '' && c.ipv6 === '1' && c.nat6 === '') {
                missing.push('IPv6');
            }
            if (missing.length === 0) {
                run();
                return;
            }
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_WARNING,
                title: "{{ lang._('No outbound NAT') }}",
                message: "{{ lang._('No NAT sources for') }} " + missing.join(" {{ lang._('and') }} ")
                    + ". {{ lang._('The inner-source block drops everything a LAN sends into a tunnel without outbound NAT (finding nat-missing). Create it anyway?') }}",
                buttons: [
                    {label: "{{ lang._('Cancel') }}", action: function (d) { d.close(); }},
                    {label: "{{ lang._('Create anyway') }}", cssClass: 'btn-warning', action: function (d) { d.close(); run(); }}
                ]
            });
        }

        function openRebind(t) {
            loadOptions(function () {
                fillSelect('#rebind\\.wan', options.wans, options.wans.length ? [options.wans[0].value] : []);
                fillSelect('#rebind\\.stale', [{value: '', label: "{{ lang._('(keep every route)') }}"}].concat(options.stale_routes), ['']);
                $('#wgct-rebind-errors').empty();
                $('#btn_dialogRebind_save').off('click').on('click', function () {
                    $('#btn_dialogRebind_save').prop('disabled', true);
                    $('#btn_dialogRebind_save_progress').addClass('fa fa-spinner fa-pulse');
                    ajaxCall('/api/wgclienttunnels/tunnels/rebind/' + t.uuid, getFormData('frm_dialogRebind'), function (r, status) {
                        $('#btn_dialogRebind_save').prop('disabled', false);
                        $('#btn_dialogRebind_save_progress').removeClass('fa fa-spinner fa-pulse');
                        refreshAll();
                        /* saved === true even with an apply error still means the route write happened:
                         * close and show it (changes plus the apply error), never leave it stuck behind the
                         * form (review finding 3) */
                        if (status === 'success' && r && r.saved === true) {
                            $('#dialogRebind').modal('hide');
                            showResult(titleText("{{ lang._('Rebind') }} " + plain(t.name)), r, status);
                            return;
                        }
                        var box = $('#wgct-rebind-errors').empty();
                        $.each(errorList(r, status), function (i, m) { box.append($('<div class="alert alert-danger"/>').text(m)); });
                    });
                });
                $('#dialogRebind').modal('show');
            });
        }

        /* ---- Edit (spec 6.5) ---- */

        /* the tunnel whose Edit dialog is open: {uuid, name (decoded), form (the prefill)} */
        var editState = null;
        /* the last parsed IPv6 list of the replacement config (as lastV6 for Create) */
        var lastEditV6 = null;
        /* wgct_is_nat_interface_key(): the NAT sources shown as checkboxes; everything else is a token */
        var natInterfaceKey = /^(wan|lan|opt\d+)$/;

        /* the interface NAT sources as checkboxes. A current source the choices lack (a disabled interface)
         * is still shown, ticked, so an unchanged Save never deletes it (ruling 14). */
        function natChecks(box, items, selected) {
            var choices = [];
            $.each(items, function (i, it) {
                if (it.kind === 'interface') {
                    choices.push(it);
                }
            });
            $.each(selected, function (i, v) {
                if (natInterfaceKey.test(v) && !choices.some(function (it) { return it.value === v; })) {
                    choices.push({value: v, label: v});
                }
            });
            box.empty();
            $.each(choices, function (i, it) {
                box.append($('<label style="display:block; font-weight:normal; margin:0;"/>').append(
                    $('<input type="checkbox"/>').val(it.value).prop('checked', selected.indexOf(it.value) !== -1),
                    ' ', $('<span/>').text(plain(it.label))));
            });
        }

        /* the alias NAT sources as core's token list; a current alias the choices lack stays selected */
        function natTokens(select, items, selected) {
            select.empty();
            var seen = [];
            $.each(items, function (i, it) {
                if (it.kind === 'alias') {
                    seen.push(it.value);
                    select.append($('<option/>').val(it.value).text(plain(it.label)).prop('selected', selected.indexOf(it.value) !== -1));
                }
            });
            $.each(selected, function (i, v) {
                if (!natInterfaceKey.test(v) && seen.indexOf(v) === -1) {
                    select.append($('<option/>').val(v).text(plain(v)).prop('selected', true));
                }
            });
            formatTokenizersUI();
        }

        function editRows() {
            var text = $('#edit\\.config').val();
            var swap = $.trim(text) !== '';
            var box = $('#edit\\.ipv6');
            var canOn = editState.form.ipv6 === true || wgPublic(text).v6.length > 0;
            box.prop('disabled', !canOn);
            if (!canOn) {
                box.prop('checked', false);
            }
            $('#row_edit\\.unique').toggle(swap && box.prop('checked'));
            $('#row_edit\\.nat6').toggle(box.prop('checked'));
        }

        /* rulings 3 and 4 for a replacement config: unique addressing on by default when its IPv6 address is
         * on another instance or the managed tunnels use fd00::N:1 */
        function editDefaults() {
            var p = wgPublic($('#edit\\.config').val());
            var key = p.v6.slice().sort().join(',');
            if (key !== lastEditV6) {
                lastEditV6 = key;
                var known = $.map(editState.form.ipv6_others, expand6);
                var shared = false;
                $.each(p.v6, function (i, a) {
                    if (known.indexOf(expand6(a)) !== -1) {
                        shared = true;
                    }
                });
                $('#edit\\.unique').prop('checked', p.v6.length > 0 ? (editState.form.unique_convention || shared) : editState.form.unique === true);
            }
            editRows();
        }

        function editMeasure() {
            var text = $('#edit\\.config').val();
            measureMtu($.trim(text) !== '' ? wgPublic(text).endpoint_ip : plain(editState.form.endpoint_ip),
                $('#edit\\.wan').val() || plain(editState.form.wan),
                $('#edit\\.mtu'), $('#wgct-edit-mtu-why'), $('#wgct-edit-measure'));
        }

        function openEdit(t) {
            /* POST like the lists: the prefill and the choices change with every action */
            ajaxCall('/api/wgclienttunnels/tunnels/edit_form/' + t.uuid, {}, function (data, status) {
                if (!data || status !== 'success' || data.status !== 'ok') {
                    showResult(titleText("{{ lang._('Edit') }} " + plain(t.name)), data, status);
                    return;
                }
                var f = data.form;
                editState = {uuid: t.uuid, name: plain(f.name), form: f};
                lastEditV6 = null;
                $('#edit\\.name').val(plain(f.name) + ' (' + plain(f.device) + ', ' + plain(f.interface) + ')');
                $('#edit\\.config').val('');
                $('#edit\\.monitor').val(plain(f.monitor));
                $('#edit\\.mtu').val(f.mtu);
                var wans = f.wan ? [] : [{value: '', label: "{{ lang._('(unbound: Rebind binds it to a WAN)') }}"}];
                wans = wans.concat(data.wans);
                if (f.wan && !data.wans.some(function (w) { return w.value === f.wan; })) {
                    wans.push({value: f.wan, label: f.wan});
                }
                fillSelect('#edit\\.wan', wans, [f.wan]);
                $('#edit\\.ipv6').prop('checked', f.ipv6 === true);
                $('#edit\\.unique').prop('checked', f.unique === true);
                natChecks($('#wgct-edit-nat4'), data.nat_sources, f.nat4);
                natChecks($('#wgct-edit-nat6'), data.nat_sources, f.nat6);
                natTokens($('#edit\\.nat4'), data.nat_sources, f.nat4);
                natTokens($('#edit\\.nat6'), data.nat_sources, f.nat6);
                var kept = $('#wgct-edit-kept').empty();
                $.each(f.nat_kept, function (i, k) { kept.append($('<div/>').text(plain(k))); });
                $('#wgct-edit-kept-wrap').toggle(f.nat_kept.length > 0);
                $('#wgct-edit-mtu-why').text(f.mtu_effective !== f.mtu
                    ? "{{ lang._('The interface MTU overrides this value (finding mtu-override):') }} " + f.mtu_effective : '');
                $('#wgct-edit-errors').empty();
                handleFormValidation('frm_dialogEdit', {});
                editRows();
                $('#dialogEdit').modal('show');
            });
        }

        /* the form, with each family's ticked interfaces and alias tokens as one comma list (edit.nat4/6) */
        function editData() {
            var data = getFormData('frm_dialogEdit');
            $.each(['4', '6'], function (i, f) {
                var list = $('#wgct-edit-nat' + f + ' input:checked').map(function () { return $(this).val(); }).get();
                var tokens = data.edit['nat' + f];
                list = list.concat(tokens ? String(tokens).split(',') : []);
                data.edit['nat' + f] = $.grep(list, function (v) { return v !== ''; }).join(',');
            });
            return data;
        }

        /* preview (dry=1) first: the confirmation lists exactly what changes and which apply runs */
        function submitEdit() {
            var st = editState;
            var url = '/api/wgclienttunnels/tunnels/edit/' + st.uuid;
            var title = titleText("{{ lang._('Edit') }} " + st.name);
            var data = editData();
            var busy = function (on) {
                $('#btn_dialogEdit_save').prop('disabled', on);
                $('#btn_dialogEdit_save_progress').toggleClass('fa fa-spinner fa-pulse', on);
            };
            var formErrors = function (r, status) {
                handleFormValidation('frm_dialogEdit', (status === 'success' && r && r.validations) || {});
                var box = $('#wgct-edit-errors').empty();
                $.each(errorList(r, status), function (i, m) { box.append($('<div class="alert alert-danger"/>').text(m)); });
            };
            busy(true);
            ajaxCall(url, $.extend({}, data, {dry: '1'}), function (preview, previewStatus) {
                busy(false);
                /* a refusal with field messages only has no error lines: result 'failed' decides, not errorList */
                if (!preview || preview.result === 'failed' || errorList(preview, previewStatus).length > 0) {
                    formErrors(preview, previewStatus);
                    return;
                }
                handleFormValidation('frm_dialogEdit', {});
                if (resultLines(preview).length === 0) {
                    $('#wgct-edit-errors').empty().append($('<div class="alert alert-info"/>').text("{{ lang._('Nothing to change.') }}"));
                    return;
                }
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_WARNING,
                    title: title,
                    message: resultBody(preview, previewStatus),
                    buttons: [
                        {label: "{{ lang._('Cancel') }}", action: function (d) { d.close(); }},
                        {label: "{{ lang._('Save') }}", cssClass: 'btn-primary', action: function (d) {
                            d.close();
                            busy(true);
                            ajaxCall(url, data, function (r, status) {
                                busy(false);
                                /* every reply: a failure after the save still changed the tunnel */
                                refreshAll();
                                if (status === 'success' && r && (r.saved === true || r.result === 'unchanged')) {
                                    $('#dialogEdit').modal('hide');
                                    showResult(title, r, status, r.saved === true ? st.uuid : null, st.name);
                                    return;
                                }
                                formErrors(r, status);
                            });
                        }}
                    ]
                });
            });
        }

        /* ---- the lists ---- */

        /* the managed tunnels: core's grid over search_grid (POST, like every core grid), which pages,
         * sorts and searches server side. No selection column and no add/edit/delete: the row commands are
         * the plugin's own actions, Rebind and Apply only on the rows whose findings call for them. */
        var tunnelsGrid = $("#{{ formGridTunnels['table_id'] }}").UIBootgrid({
            search: '/api/wgclienttunnels/tunnels/search_grid',
            options: {
                selection: false,
                responsive: true,
                formatters: gridFormatters
            },
            commands: {
                wgct_edit: {
                    classname: 'fa fa-fw fa-pencil',
                    title: "{{ lang._('Edit') }}",
                    sequence: 5,
                    /* a row whose WireGuard instance is gone has nothing to edit */
                    filter: function (cell) { return cell.getData().device !== ''; },
                    method: function (event, cell) { openEdit(cell.getData()); }
                },
                wgct_apply: {
                    classname: 'fa fa-fw fa-play',
                    title: "{{ lang._('Run the apply the saved change still needs') }}",
                    sequence: 10,
                    filter: function (cell) { return cell.getData().apply_pending === true; },
                    method: function (event, cell) {
                        var t = cell.getData();
                        runApply(t.uuid, t.name);
                    },
                    /* the one command that finishes an interrupted Create or Edit: make it stand out */
                    onRendered: function () { this.removeClass('btn-default').addClass('btn-warning'); }
                },
                wgct_rebind: {
                    classname: 'fa fa-fw fa-link',
                    title: "{{ lang._('Rebind to a WAN') }}",
                    sequence: 20,
                    filter: function (cell) { return cell.getData().unbound === true; },
                    method: function (event, cell) { openRebind(cell.getData()); }
                },
                wgct_remove: {
                    classname: 'fa fa-fw fa-trash-o',
                    title: "{{ lang._('Remove') }}",
                    sequence: 30,
                    method: function (event, cell) {
                        var t = cell.getData();
                        confirmAction(titleText("{{ lang._('Remove') }} " + plain(t.name)), '/api/wgclienttunnels/tunnels/remove/' + t.uuid, "{{ lang._('Remove') }}");
                    }
                }
            }
        });

        /* the global findings and the WireGuard instances the plugin does not manage */
        function renderLists(data) {
            var banners = [];
            var ubody = $('<tbody/>');
            if (!data || data.status !== 'ok') {
                banners.push($('<div class="alert alert-danger"/>').text(data && data.errorMessage ? plain(data.errorMessage) : failedText));
            } else {
                $.each(data.global, function (i, f) {
                    banners.push($('<div class="alert alert-warning"/>').text(plain(f.code) + ': ' + plain(f.detail) + ' — ' + plain(f.fix)));
                });
                if (!data.unmanaged.length) {
                    ubody.append($('<tr/>').append($('<td colspan="5"/>').text("{{ lang._('Every WireGuard instance is managed.') }}")));
                }
                $.each(data.unmanaged, function (i, u) {
                    ubody.append($('<tr/>').append(
                        $('<td/>').append(link(u.name, links.instance)),
                        $('<td/>').text(plain(u.device)),
                        $('<td/>').append(linkOrDash(u.endpoint, links.peers)),
                        $('<td/>').append(u.enabled
                            ? $('<span/>').text("{{ lang._('yes') }}")
                            : $('<span class="label label-default"/>').text("{{ lang._('disabled') }}")),
                        $('<td/>').append($('<button type="button" class="btn btn-default btn-xs"/>')
                            .append($('<i class="fa fa-plus fa-fw"/>'), ' ', $('<span/>').text("{{ lang._('Adopt') }}"))
                            .on('click', function () {
                                confirmAction(titleText("{{ lang._('Adopt') }} " + plain(u.name)), '/api/wgclienttunnels/tunnels/adopt/' + u.uuid, "{{ lang._('Adopt') }}");
                            }))
                    ));
                });
            }
            $('#tunnel-banners').empty().append(banners);
            $('#unmanaged-table tbody').replaceWith(ubody);
        }

        /* POST, like the grid: an action's reply is followed by a fresh read, never a stored one. Only the
         * latest request renders, so a slow reply can never overwrite a newer one. */
        var listsRequest = 0;
        function refreshLists() {
            var request = ++listsRequest;
            ajaxCall('/api/wgclienttunnels/tunnels/search', {}, function (data, status) {
                if (request === listsRequest) {
                    renderLists(status === 'success' ? data : null);
                }
            });
        }

        /* after every action that can change the list, and on Refresh view */
        function refreshAll() {
            tunnelsGrid.bootgrid('reload');
            refreshLists();
        }

        /* ---- wiring ---- */

        mapDataToFormUI({'frm_general': '/api/wgclienttunnels/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                var dfObj = new $.Deferred();
                saveFormToEndpoint('/api/wgclienttunnels/settings/set', 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function () { refreshAll(); }
        });
        $('#frm_dialogCreate').prepend($('<div id="wgct-create-errors"/>'));
        $('#frm_dialogRebind').prepend($('<div id="wgct-rebind-errors"/>'));
        /* the config textbox holds the private key while it is pasted: no browser cloud spellcheck, no
         * autofill, ever sees it (review finding 6) */
        $('#create\\.config').attr({
            spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off'
        });
        $('#create\\.mtu').after($('#wgct-measure-wrap').detach().show());
        $('#create\\.config').after($('#wgct-file-wrap').detach().show());
        $('#wgct-measure').on('click', measure);
        fileLoader($('#wgct-file-btn'), $('#wgct-file'), $('#create\\.config'));
        $('#create\\.config').on('input', ipv6Defaults);
        $('#create\\.ipv6').on('change', natRows);
        $('#create\\.template').on('change', natRows);
        $('#create\\.wan').on('change', function () {
            if (wgPublic($('#create\\.config').val()).endpoint_ip) {
                measure();
            }
        });
        $('#btn_dialogCreate_save').on('click', submitCreate);
        /* the pasted config holds the private key: it never stays in the page */
        $('#dialogCreate').on('hidden.bs.modal', function () { $('#create\\.config').val(''); });
        $('#btn-create').on('click', openCreate);
        /* Edit: its own form (edit.*); the replacement config may hold a private key and never stays in the page */
        $('#frm_dialogEdit').prepend($('<div id="wgct-edit-errors"/>'));
        $('#edit\\.config').attr({spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off'});
        $('#edit\\.name').prop('readonly', true);
        $('#edit\\.mtu').after($('#wgct-edit-measure-wrap').detach().show());
        $('#edit\\.config').after($('#wgct-edit-file-wrap').detach().show());
        $('#edit\\.nat4').closest('td').prepend($('<div id="wgct-edit-nat4"/>'));
        $('#edit\\.nat6').closest('td').prepend($('<div id="wgct-edit-nat6"/>'));
        $('#edit\\.nat4').closest('td').append($('#wgct-edit-kept-wrap').detach());
        fileLoader($('#wgct-edit-file-btn'), $('#wgct-edit-file'), $('#edit\\.config'));
        $('#wgct-edit-measure').on('click', editMeasure);
        $('#edit\\.config').on('input', editDefaults);
        $('#edit\\.ipv6').on('change', editRows);
        $('#btn_dialogEdit_save').on('click', submitEdit);
        $('#dialogEdit').on('hidden.bs.modal', function () { $('#edit\\.config').val(''); });
        $('#btn-sentinel').on('click', function () {
            confirmAction("{{ lang._('Ensure sentinel') }}", '/api/wgclienttunnels/service/sentinel', "{{ lang._('Apply') }}");
        });
        $('#btn-refresh').on('click', refreshAll);
        /* the grid's own refresh button reloads the grid; bring the banners and the unmanaged list along */
        $("#{{ formGridTunnels['table_id'] }}-refresh-button").on('click', refreshLists);
        /* the grid loads itself */
        refreshLists();
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#tunnels">{{ lang._('Tunnels') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
        <div style="padding: 0 1em 1em 1em;">
            <button class="btn btn-default" id="btn-sentinel" type="button"><i class="fa fa-shield fa-fw"></i> {{ lang._('Ensure sentinel') }}</button>
            <small class="text-muted">{{ lang._('Creates or repairs NO_DEFAULT4 and NO_DEFAULT6, the address-less gateways at priority 254 on a loopback that keep every tunnel out of the default-gateway election. Shows what it would change before changing it.') }}</small>
        </div>
    </div>
    <div id="tunnels" class="tab-pane fade" style="padding: 1em;">
        <p>{{ lang._('Each managed tunnel is assembled from core configuration: its WireGuard instance and peer, its interface assignment, the /32 route that binds it to a WAN, the gateways on its interface, outbound NAT and gateway groups. Edit those on their own pages; this list follows. Create, Edit, Rebind and Remove change several of them at once. Hover a finding for what it means and where it is fixed.') }}
            <a href="/ui/interfaces/assignment">{{ lang._('Interfaces: Assignments') }}</a></p>
        <div id="tunnel-banners"></div>
        <button class="btn btn-primary" id="btn-create" type="button"><i class="fa fa-plus fa-fw"></i> {{ lang._('Create') }}</button>
        <button class="btn btn-default" id="btn-refresh" type="button"><i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh view') }}</button>
        <div style="margin-top: 1em;">
            {{ partial('layout_partials/base_bootgrid_table', formGridTunnels + {'command_width': '140', 'hide_add': true, 'hide_delete': true}) }}
        </div>
        <h4>{{ lang._('WireGuard instances the plugin does not manage') }}</h4>
        <table class="table table-striped table-condensed" id="unmanaged-table">
            <thead>
                <tr>
                    <th>{{ lang._('Instance') }}</th>
                    <th>{{ lang._('Device') }}</th>
                    <th>{{ lang._('Endpoint') }}</th>
                    <th>{{ lang._('Enabled') }}</th>
                    <th></th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>
<section class="page-content-main">
    <div class="content-box">
        <div class="col-md-12">
            <br/>
            <button class="btn btn-primary" id="reconfigureAct"
                    data-endpoint="/api/wgclienttunnels/service/reconfigure"
                    data-label="{{ lang._('Apply') }}"
                    data-error-title="{{ lang._('Error applying the WireGuard client tunnel settings') }}"
                    type="button"></button>
            <br/><br/>
        </div>
    </div>
</section>

<span id="wgct-measure-wrap" style="display: none;">
    <button type="button" class="btn btn-default btn-xs" id="wgct-measure"><i class="fa fa-tachometer fa-fw"></i> {{ lang._('Measure') }}</button>
    <small class="text-muted" id="wgct-mtu-why"></small>
</span>
<span id="wgct-file-wrap" style="display: none;">
    <br/><button type="button" class="btn btn-default btn-xs" id="wgct-file-btn"><i class="fa fa-folder-open-o fa-fw"></i> {{ lang._('Load file') }}</button>
    <input type="file" id="wgct-file" accept=".conf,text/plain" style="display: none;"/>
</span>
<span id="wgct-edit-measure-wrap" style="display: none;">
    <button type="button" class="btn btn-default btn-xs" id="wgct-edit-measure"><i class="fa fa-tachometer fa-fw"></i> {{ lang._('Measure') }}</button>
    <small class="text-muted" id="wgct-edit-mtu-why"></small>
</span>
<span id="wgct-edit-file-wrap" style="display: none;">
    <br/><button type="button" class="btn btn-default btn-xs" id="wgct-edit-file-btn"><i class="fa fa-folder-open-o fa-fw"></i> {{ lang._('Load file') }}</button>
    <input type="file" id="wgct-edit-file" accept=".conf,text/plain" style="display: none;"/>
</span>
<div id="wgct-edit-kept-wrap" style="display: none; margin-top: 0.5em;">
    <small class="text-muted">{{ lang._('Other outbound NAT rules on this interface, kept exactly as they are (edit them on Firewall: NAT: Source NAT):') }}</small>
    <div id="wgct-edit-kept" class="text-muted small"></div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': createForm, 'id': 'dialogCreate', 'label': lang._('Create tunnel')]) }}
{{ partial("layout_partials/base_dialog", ['fields': rebindForm, 'id': 'dialogRebind', 'label': lang._('Rebind tunnel')]) }}
{{ partial("layout_partials/base_dialog", ['fields': editForm, 'id': 'dialogEdit', 'label': lang._('Edit tunnel')]) }}
