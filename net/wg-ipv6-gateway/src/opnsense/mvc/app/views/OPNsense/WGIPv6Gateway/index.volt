{#
 # Copyright (C) 2026 cayossarian (Bill Flood)
 # All rights reserved.
 # BSD 2-Clause License
 #}

<style>
    .wgct-table a.wgct-link { color: inherit; text-decoration: none; border-bottom: 1px dotted currentColor; }
    .wgct-table a.wgct-link:hover { text-decoration: none; border-bottom-style: solid; }
    .wgct-table td.wgct-nowrap { white-space: nowrap; }
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

        function link(text, href) {
            return $('<a/>').addClass('wgct-link').attr('href', href).text(text);
        }

        function gwCell(name, status, statusText, held) {
            var cell = $('<td class="wgct-nowrap"/>');
            if (name === null) {
                return cell.text('—');
            }
            cell.append(link(name, links.gateways));
            if (statusText) {
                var cls;
                if (status === 'none') {
                    cls = 'label-success';
                } else if (status === 'loss' || status === 'delay' || status === 'delay+loss' || status === 'force_down') {
                    cls = 'label-warning';
                } else {
                    cls = 'label-danger';
                }
                cell.append(' ', $('<span class="label"/>').addClass(cls).text(statusText));
            }
            if (held) {
                cell.append(' ', $('<span class="label label-info"/>').text("{{ lang._('held by mirror') }}"));
            }
            return cell;
        }

        function findingBadges(findings) {
            var cell = $('<td/>');
            if (!findings.length) {
                return cell.text('—');
            }
            $.each(findings, function (i, f) {
                cell.append($('<span class="label" style="display:inline-block; margin:1px;"/>')
                    .addClass(f.blocking ? 'label-danger' : 'label-warning')
                    .attr('title', f.detail + ' — ' + f.fix)
                    .text(f.code), ' ');
            });
            return cell;
        }

        /* ---- action results ---- */

        /* status is jQuery's: 'success' only for a completed request whose reply parsed as JSON. An error
         * page, a timeout or a login redirect reaches the callback as a jqXHR without any of our keys,
         * and must never read as "Nothing to change" (review I4). */
        function errorList(r, status) {
            if (!r || (status !== undefined && status !== 'success')
                || !('ok' in r || 'result' in r || 'status' in r || 'errors' in r)) {
                return [r && r.errorMessage ? r.errorMessage : failedText];
            }
            var out = [];
            $.each(r.errors || [], function (k, m) { out.push(m); });
            if (r.result === 'failed' && out.length === 0 && $.isEmptyObject(r.validations || {})) {
                out.push(failedText);
            }
            return out;
        }

        function resultLines(r) {
            var lines = [];
            $.each((r && r.changes) || [], function (i, c) { lines.push(c); });
            $.each((r && r.apply) || [], function (i, s) { lines.push('configctl ' + s.action + ': ' + s.result); });
            if (r && r.after && r.after.reconcile) {
                lines.push("{{ lang._('alarm replayed for') }}: " + (r.after.replayed.length ? r.after.replayed.join(', ') : '—'));
                lines.push("{{ lang._('reconcile') }}: " + r.after.reconcile);
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
            ajaxCall('/api/wgipv6gateway/tunnels/apply/' + uuid, {}, function (r, status) {
                showResult("{{ lang._('Apply') }} " + name, r, status, uuid);
            });
        }

        /* applyUuid: a tunnel that is saved (Create, or an earlier Apply); when its apply did not complete,
         * the dialog offers "Apply again" (ruling 20) -- the finding apply-pending stays until one completes */
        function showResult(title, r, status, applyUuid) {
            var failed = errorList(r, status).length > 0;
            var buttons = [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}];
            if (failed && applyUuid) {
                buttons.unshift({
                    label: "{{ lang._('Apply again') }}",
                    cssClass: 'btn-primary',
                    action: function (d) { d.close(); runApply(applyUuid, title); }
                });
            }
            BootstrapDialog.show({
                type: failed ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_INFO,
                title: title,
                message: resultBody(r, status),
                buttons: buttons,
                onhidden: function () { refresh(); }
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
                            ajaxCall(url, {}, function (r, status) { showResult(title, r, status); });
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
            ajaxGet('/api/wgipv6gateway/tunnels/options', {}, function (data, status) {
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
                select.append($('<option/>').val(it.value).text(it.label).prop('selected', selected.indexOf(it.value) !== -1));
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

        /* rulings 3 and 4: IPv6 only when the config has an address; unique addressing on by default when that
         * address is already on a WireGuard instance or the managed tunnels use fd00::N:1. A missed match only
         * leaves the box unchecked, and the planner then refuses the duplicate explicitly. */
        function ipv6Defaults() {
            if (!options) {
                return;
            }
            var p = wgPublic($('#create\\.config').val());
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

        function measure() {
            var p = wgPublic($('#create\\.config').val());
            var wan = $('#create\\.wan').val();
            var why = $('#wgct-mtu-why');
            if (!p.endpoint_ip || !wan) {
                why.text("{{ lang._('Paste the config and choose the WAN first.') }}");
                return;
            }
            $('#wgct-measure').prop('disabled', true);
            why.text("{{ lang._('Measuring the path; this takes up to half a minute...') }}");
            ajaxCall('/api/wgipv6gateway/tunnels/measure_mtu', {wan: wan, endpoint: p.endpoint_ip}, function (r, status) {
                $('#wgct-measure').prop('disabled', false);
                if (status === 'success' && r && r.ok) {
                    $('#create\\.mtu').val(r.mtu);
                    why.text(r.why);
                } else {
                    why.text(errorList(r, status).join('; '));
                }
            });
        }

        function openCreate() {
            loadOptions(function () {
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
            var run = function () {
                $('#btn_dialogCreate_save').prop('disabled', true);
                $('#btn_dialogCreate_save_progress').addClass('fa fa-spinner fa-pulse');
                ajaxCall('/api/wgipv6gateway/tunnels/create', data, function (r, status) {
                    $('#btn_dialogCreate_save').prop('disabled', false);
                    $('#btn_dialogCreate_save_progress').removeClass('fa fa-spinner fa-pulse');
                    if (status === 'success' && r && r.result === 'saved') {
                        $('#dialogCreate').modal('hide');
                        showResult("{{ lang._('Create tunnel') }}", r, status, r.uuid);
                        return;
                    }
                    handleFormValidation('frm_dialogCreate', (status === 'success' && r && r.validations) || {});
                    var box = $('#wgct-create-errors').empty();
                    $.each(errorList(r, status), function (i, m) { box.append($('<div class="alert alert-danger"/>').text(m)); });
                    if (status !== 'success') {
                        /* the request died after the save, perhaps: the list shows apply-pending and an Apply button then */
                        box.append($('<div class="alert alert-warning"/>').text("{{ lang._('If the tunnel appears in the list after Refresh view with the finding apply-pending, it was saved: press its Apply button.') }}"));
                    }
                });
            };
            var c = data.create;
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
                    ajaxCall('/api/wgipv6gateway/tunnels/rebind/' + t.uuid, getFormData('frm_dialogRebind'), function (r, status) {
                        if (errorList(r, status).length) {
                            var box = $('#wgct-rebind-errors').empty();
                            $.each(errorList(r, status), function (i, m) { box.append($('<div class="alert alert-danger"/>').text(m)); });
                            return;
                        }
                        $('#dialogRebind').modal('hide');
                        showResult("{{ lang._('Rebind') }} " + t.name, r, status);
                    });
                });
                $('#dialogRebind').modal('show');
            });
        }

        /* ---- the lists ---- */

        function actionButtons(t) {
            var cell = $('<td class="wgct-nowrap"/>');
            var codes = $.map(t.findings, function (f) { return f.code; });
            if (codes.indexOf('apply-pending') !== -1) {
                cell.append($('<button type="button" class="btn btn-warning btn-xs"/>')
                    .attr('title', "{{ lang._('Run the tunnel apply again') }}")
                    .append($('<i class="fa fa-play fa-fw"/>'), ' ', $('<span/>').text("{{ lang._('Apply') }}"))
                    .on('click', function () { runApply(t.uuid, t.name || t.uuid); }), ' ');
            }
            if (codes.indexOf('unbound') !== -1) {
                cell.append($('<button type="button" class="btn btn-default btn-xs"/>')
                    .attr('title', "{{ lang._('Rebind to a WAN') }}")
                    .append($('<i class="fa fa-link fa-fw"/>'))
                    .on('click', function () { openRebind(t); }), ' ');
            }
            cell.append($('<button type="button" class="btn btn-default btn-xs"/>')
                .attr('title', "{{ lang._('Remove') }}")
                .append($('<i class="fa fa-trash fa-fw"/>'))
                .on('click', function () {
                    confirmAction("{{ lang._('Remove') }} " + (t.name || t.uuid), '/api/wgipv6gateway/tunnels/remove/' + t.uuid, "{{ lang._('Remove') }}");
                }));
            return cell;
        }

        function render(data) {
            var banners = [];
            var tbody = $('<tbody/>');
            var ubody = $('<tbody/>');
            if (!data || data.status !== 'ok') {
                banners.push($('<div class="alert alert-danger"/>').text(data && data.errorMessage ? data.errorMessage : failedText));
            } else {
                $.each(data.global, function (i, f) {
                    banners.push($('<div class="alert alert-warning"/>').text(f.code + ': ' + f.detail + ' — ' + f.fix));
                });
                if (!data.tunnels.length) {
                    tbody.append($('<tr/>').append($('<td colspan="10"/>').text("{{ lang._('No managed tunnels.') }}")));
                }
                $.each(data.tunnels, function (i, t) {
                    var name = $('<td class="wgct-nowrap"/>').append(link(t.name || t.uuid, links.instance));
                    if (t.device) {
                        var ifaceLabel = t.interface_descr || t.interface;
                        name.append($('<br/>'), $('<small class="text-muted"/>').append(t.interface
                            ? link(t.device + (ifaceLabel ? ' / ' + ifaceLabel : ''), links.iface + encodeURIComponent(t.interface))
                            : link(t.device + ' — ' + "{{ lang._('not assigned') }}", links.assignments)));
                    }
                    if (!t.enabled) {
                        name.append(' ', $('<span class="label label-default"/>').text("{{ lang._('disabled') }}"));
                    }
                    var nat = [];
                    if (t.nat_display.inet.length) nat.push('v4: ' + t.nat_display.inet.join(', '));
                    if (t.nat_display.inet6.length) nat.push('v6: ' + t.nat_display.inet6.join(', '));
                    var mtuCell = $('<td class="wgct-nowrap"/>').text(t.mtu);
                    if (t.clamp) {
                        var clampParts = [];
                        if (t.clamp.v4 !== null) clampParts.push('v4 ' + t.clamp.v4);
                        if (t.clamp.v6 !== null) clampParts.push('v6 ' + t.clamp.v6);
                        if (clampParts.length) {
                            mtuCell.append($('<br/>'), $('<small class="text-muted"/>').text('MSS ' + clampParts.join(' / ')));
                        }
                    }
                    tbody.append($('<tr/>').append(
                        name,
                        $('<td class="wgct-nowrap"/>').append(t.endpoint ? link(t.endpoint, links.peers) : $('<span/>').text('—')),
                        $('<td/>').append(t.bound_wan ? link(t.bound_wan, links.routes) : $('<span/>').text('—')),
                        mtuCell,
                        gwCell(t.gw4, t.gw4_status, t.gw4_status_text, t.held),
                        gwCell(t.gw6, t.gw6_status, t.gw6_status_text, false),
                        $('<td/>').append(nat.length ? link(nat.join('; '), links.nat) : $('<span/>').text('—')),
                        $('<td/>').append(t.groups.length ? link(t.groups.join(', '), links.groups) : $('<span/>').text('—')),
                        findingBadges(t.findings),
                        actionButtons(t)
                    ));
                });
                if (!data.unmanaged.length) {
                    ubody.append($('<tr/>').append($('<td colspan="5"/>').text("{{ lang._('Every WireGuard instance is managed.') }}")));
                }
                $.each(data.unmanaged, function (i, u) {
                    ubody.append($('<tr/>').append(
                        $('<td/>').append(link(u.name, links.instance)),
                        $('<td/>').text(u.device),
                        $('<td/>').append(u.endpoint ? link(u.endpoint, links.peers) : $('<span/>').text('—')),
                        $('<td/>').append(u.enabled
                            ? $('<span/>').text("{{ lang._('yes') }}")
                            : $('<span class="label label-default"/>').text("{{ lang._('disabled') }}")),
                        $('<td/>').append($('<button type="button" class="btn btn-default btn-xs"/>')
                            .append($('<i class="fa fa-plus fa-fw"/>'), ' ', $('<span/>').text("{{ lang._('Adopt') }}"))
                            .on('click', function () {
                                confirmAction("{{ lang._('Adopt') }} " + u.name, '/api/wgipv6gateway/tunnels/adopt/' + u.uuid, "{{ lang._('Adopt') }}");
                            }))
                    ));
                });
            }
            $('#tunnel-banners').empty().append(banners);
            $('#tunnels-table tbody').replaceWith(tbody);
            $('#unmanaged-table tbody').replaceWith(ubody);
        }

        function refresh() {
            ajaxGet('/api/wgipv6gateway/tunnels/search', {}, function (data, status) { render(status === 'success' ? data : null); });
        }

        /* ---- wiring ---- */

        mapDataToFormUI({'frm_general': '/api/wgipv6gateway/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                var dfObj = new $.Deferred();
                saveFormToEndpoint('/api/wgipv6gateway/settings/set', 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function () { refresh(); }
        });
        $('#frm_dialogCreate').prepend($('<div id="wgct-create-errors"/>'));
        $('#frm_dialogRebind').prepend($('<div id="wgct-rebind-errors"/>'));
        $('#create\\.mtu').after($('#wgct-measure-wrap').detach().show());
        $('#create\\.config').after($('#wgct-file-wrap').detach().show());
        $('#wgct-measure').on('click', measure);
        $('#wgct-file-btn').on('click', function () { $('#wgct-file').click(); });
        $('#wgct-file').on('change', function () {
            var file = this.files && this.files[0];
            if (!file) {
                return;
            }
            var reader = new FileReader();
            reader.onload = function () {
                $('#create\\.config').val(reader.result).trigger('input');
                $('#wgct-file').val('');
            };
            reader.readAsText(file);
        });
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
        $('#btn-sentinel').on('click', function () {
            confirmAction("{{ lang._('Ensure sentinel') }}", '/api/wgipv6gateway/service/sentinel', "{{ lang._('Apply') }}");
        });
        $('#btn-refresh').on('click', refresh);
        refresh();
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
        <p>{{ lang._('Each managed tunnel is assembled from core configuration: its WireGuard instance and peer, its interface assignment, the /32 route that binds it to a WAN, the gateways on its interface, outbound NAT and gateway groups. Edit those on their own pages; this list follows. Create, Rebind and Remove change several of them at once. Hover a finding for what it means and where it is fixed.') }}
            <a href="/ui/interfaces/assignment">{{ lang._('Interfaces: Assignments') }}</a></p>
        <div id="tunnel-banners"></div>
        <button class="btn btn-primary" id="btn-create" type="button"><i class="fa fa-plus fa-fw"></i> {{ lang._('Create') }}</button>
        <button class="btn btn-default" id="btn-refresh" type="button"><i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh view') }}</button>
        <table class="table table-striped table-condensed wgct-table" id="tunnels-table" style="margin-top: 1em;">
            <thead>
                <tr>
                    <th>{{ lang._('Tunnel') }}</th>
                    <th>{{ lang._('Endpoint') }}</th>
                    <th>{{ lang._('Bound WAN') }}</th>
                    <th>{{ lang._('MTU') }}</th>
                    <th>{{ lang._('IPv4 gateway') }}</th>
                    <th>{{ lang._('IPv6 gateway') }}</th>
                    <th>{{ lang._('Outbound NAT') }}</th>
                    <th>{{ lang._('Groups') }}</th>
                    <th>{{ lang._('Findings') }}</th>
                    <th>{{ lang._('Actions') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        <h4>{{ lang._('WireGuard instances the plugin does not manage') }}</h4>
        <table class="table table-striped table-condensed wgct-table" id="unmanaged-table">
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
                    data-endpoint="/api/wgipv6gateway/service/reconfigure"
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

{{ partial("layout_partials/base_dialog", ['fields': createForm, 'id': 'dialogCreate', 'label': lang._('Create tunnel')]) }}
{{ partial("layout_partials/base_dialog", ['fields': rebindForm, 'id': 'dialogRebind', 'label': lang._('Rebind tunnel')]) }}
