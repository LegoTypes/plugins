{#
 # Copyright (C) 2026 cayossarian
 # All rights reserved.
 # BSD 2-Clause License
 #}

<script>
    $(document).ready(function () {
        /* the exact inverse of core's htmlspecialchars(..., ENT_NOQUOTES): &lt; &gt; and &amp; back, nothing else
           decoded */
        function plain(s) {
            return String(s === undefined || s === null ? '' : s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        }
        function yesno(b) {
            return b ? "{{ lang._('yes') }}" : "{{ lang._('no') }}";
        }
        function check(c) {
            if (!c) { return "{{ lang._('not yet') }}"; }
            return (c.ok ? "{{ lang._('ok') }}" : "{{ lang._('failed') }}") + ' (' + plain(c.member) + ', ' + new Date(c.at * 1000).toLocaleString() + ')';
        }
        /* the member's reading: only a settled window qualifies it for choice */
        var readings = {
            'settled': "{{ lang._('settled') }}",
            'young': "{{ lang._('young (window not yet full)') }}",
            'cached': "{{ lang._('cached (last reading of the gateway watcher)') }}",
            'none': "{{ lang._('none') }}"
        };
        /* loaded, verifying (the ruleset changed since the last evaluation) or the named problems; then
           the addresses the footprint block keeps while the plugin may still be using them, when there are any */
        function rulesText(data) {
            var r = data.rules || {};
            var text = r.state === 'loaded' ? "{{ lang._('yes') }}"
                : (r.state === 'verifying' ? "{{ lang._('verifying') }}"
                    : "{{ lang._('no') }}" + ((r.problems || []).length ? ': ' + plain(r.problems.join('; ')) : ''));
            if (r.verified_at !== null && r.verified_at !== undefined) {
                text += ' (' + "{{ lang._('verified') }} " + new Date(r.verified_at * 1000).toLocaleString() + ')';
            }
            var footprints = [];
            if ((data.addresses || []).length <= 1) {
                footprints = data.footprint ? [data.footprint] : [];
            } else {
                $.each(data.routes, function (addr, entry) {
                    if (entry.footprint) {
                        footprints.push(addr);
                    }
                });
            }
            return text + ', ' + (data.counter_armed && data.blocked !== null
                ? data.blocked + " {{ lang._('blocked packets') }}" : "{{ lang._('counter not armed') }}")
                + (footprints.length ? "; {{ lang._('footprint block for') }} " + plain(footprints.join(', ')) : '');
        }
        /* a route as a route row shows it: its next hop and device, or reject, with its flags */
        function routeText(route) {
            return route.present
                ? plain((route.reject ? "{{ lang._('reject') }}" : route.gateway + ' ' + route.interface)
                    + ' [' + (route.flags || []).join(' ') + ']'
                    + (route.ours ? '' : " {{ lang._('(not made by this plugin)') }}"))
                : "{{ lang._('absent') }}";
        }
        function lastDown(d) {
            return d ? new Date(d.at * 1000).toLocaleString() + ': ' + plain(d.reason) : '';
        }
        function row(label, value) {
            return $('<tr/>').append($('<th/>').text(label)).append($('<td/>').text(value));
        }
        function refreshState() {
            ajaxGet('/api/unboundupstream/service/state', {}, function (data) {
                var body = $('#unboundupstream-state tbody').empty();
                var members = $('#unboundupstream-members tbody').empty();
                if (!data || data.status === 'failed') {
                    body.append($('<tr/>').append($('<td colspan="2"/>').text("{{ lang._('Status unavailable.') }}")));
                    return;
                }
                var route = data.route || {};
                var contract = data.contract || {};
                body.append(row("{{ lang._('Mode') }}", plain(data.mode) + (data.dry_run ? " ({{ lang._('dry run') }})" : '')));
                body.append(row("{{ lang._('Member') }}", data.member === null ? '' : plain(data.member) + ' ({{ lang._('tier') }} ' + data.tier + ')'));
                body.append(row("{{ lang._('Unbound') }}", data.unbound.running ? (data.unbound.control_ok ? "{{ lang._('running') }}" : "{{ lang._('running, control channel silent') }}") : "{{ lang._('not running') }}"));
                body.append(row("{{ lang._('Live root forwarders') }}", data.live_root === null ? "{{ lang._('unknown') }}" : plain(data.live_root.join(', '))));
                body.append(row("{{ lang._('Configured root forwarders') }}", plain((data.configured_root.addrs || []).join(', ')) + (data.configured_root.tls ? ' (TLS)' : '')));
                body.append(row("{{ lang._('TLS flag last applied') }}", data.tls_applied === null ? '' : yesno(data.tls_applied)));
                /* one address: the route row as it always read; several: a row for each */
                if ((data.addresses || []).length <= 1) {
                    body.append(row("{{ lang._('Resolver route') }}", routeText(route)));
                } else {
                    $.each(data.routes, function (addr, r) {
                        body.append(row("{{ lang._('Resolver route') }} (" + plain(addr) + ')', routeText(r)));
                    });
                }
                body.append(row("{{ lang._('Rules loaded') }}", rulesText(data)));
                body.append(row("{{ lang._('Last direct check') }}", check((data.checks || {}).direct)));
                body.append(row("{{ lang._('Last check through Unbound') }}", check((data.checks || {}).unbound)));
                var ls = data.last_switch;
                body.append(row("{{ lang._('Last switch') }}", ls ? new Date(ls.at * 1000).toLocaleString() + ': ' + plain(ls.from) + ' -> ' + plain(ls.to) + ' (' + plain(ls.reason) + ')' : ''));
                body.append(row("{{ lang._('Next action') }}", plain(data.next.action) + (data.next.reasons.length ? ' (' + plain(data.next.reasons.join('; ')) + ')' : '')));
                $.each(data.members || [], function (i, m) {
                    members.append($('<tr/>')
                        .append($('<td/>').text(plain(m.name)))
                        .append($('<td/>').text(m.tier))
                        .append($('<td/>').text(plain(m.resolver)))
                        .append($('<td/>').text(plain(readings[m.kind] || m.kind)))
                        .append($('<td/>').text(plain(m.verdict === null ? "{{ lang._('up') }}" : m.verdict)))
                        .append($('<td/>').text(yesno(m.usable)))
                        .append($('<td/>').text(m.resolver_failed_for === null ? '' : m.resolver_failed_for + ' s'))
                        .append($('<td/>').text(plain(m.healthy_for_text)))
                        .append($('<td/>').text(lastDown(m.last_down))));
                });
                var notes = [];
                $.each(contract.failures || [], function (i, f) { notes.push("{{ lang._('Tunnel mode refused:') }} " + plain(f)); });
                $.each(contract.notes || [], function (i, n) { notes.push(plain(n)); });
                /* one line per refusal or note, each set as text */
                var box = $('#unboundupstream-notes').empty();
                $.each(notes, function (i, n) { box.append($('<div/>').text(n)); });
                box.toggle(notes.length > 0);
            });
        }

        mapDataToFormUI({'frm_general': '/api/unboundupstream/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        /* the per-member resolvers: each row is saved by its own dialog, then applied (below) */
        $('#grid-resolvers').UIBootgrid({
            search: '/api/unboundupstream/settings/search_resolver',
            get: '/api/unboundupstream/settings/get_resolver/',
            set: '/api/unboundupstream/settings/set_resolver/',
            add: '/api/unboundupstream/settings/add_resolver/',
            del: '/api/unboundupstream/settings/del_resolver/'
        });
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                var dfObj = new $.Deferred();
                saveFormToEndpoint('/api/unboundupstream/settings/set', 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function () { refreshState(); }
        });
        /* a row the grid saved or deleted is applied at once, as Apply applies the settings it saves: evaluations
           read the saved rows every minute, and only Apply's filter reload renders the rules a new resolver needs,
           so a row saved but not applied would fall back to Unbound's own forwarders */
        $(document).on('settings-changed', function () {
            ajaxCall('/api/unboundupstream/service/reconfigure', {}, function (data, status) {
                if (status === 'success' && data && String(data.status).toLowerCase().trim() === 'ok') {
                    $('#change_message_base_form').hide();
                } else {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_WARNING,
                        title: "{{ lang._('Error reconfiguring service.') }}",
                        message: $('<div/>').text(plain(data && (data.status_msg || data.status))),
                        draggable: true
                    });
                }
                refreshState();
            });
        });
        refreshState();
        /* the plugin evaluates every minute and on gateway events: keep the page current */
        setInterval(refreshState, 10000);
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
</div>
<div class="content-box">
    <table class="table table-condensed">
        <tr><td><h3>{{ lang._('Per-member resolvers') }}</h3>
            <p>{{ lang._('A row takes effect once saved or deleted. The settings above still need Apply.') }}</p>
        </td></tr>
        <tr><td>
            <table id="grid-resolvers" class="table table-condensed table-hover table-striped"
                   data-editDialog="DialogResolver">
                <thead>
                    <tr>
                        <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">
                            {{ lang._('ID') }}</th>
                        <th data-column-id="gateway" data-type="string">{{ lang._('Member') }}</th>
                        <th data-column-id="address" data-type="string">{{ lang._('Resolver') }}</th>
                        <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">
                            {{ lang._('Commands') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
                <tfoot>
                    <tr>
                        <td></td>
                        <td>
                            <button data-action="add" type="button" class="btn btn-xs btn-primary">
                                <span class="fa fa-fw fa-plus"></span></button>
                            <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default">
                                <span class="fa fa-fw fa-trash-o"></span></button>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </td></tr>
    </table>
</div>
<div class="content-box">
    <div class="alert alert-info" id="unboundupstream-notes" style="display: none;"></div>
    <p>{{ lang._("Unbound's own settings page keeps showing its configured forwarders while the tunnel is in use") }}</p>
    <table class="table table-condensed" id="unboundupstream-state">
        <tbody></tbody>
    </table>
    <table class="table table-condensed" id="unboundupstream-members">
        <thead>
            <tr>
                <th>{{ lang._('Member') }}</th>
                <th>{{ lang._('Tier') }}</th>
                <th>{{ lang._('Resolver') }}</th>
                <th>{{ lang._('Reading') }}</th>
                <th>{{ lang._('Verdict') }}</th>
                <th>{{ lang._('Usable') }}</th>
                <th>{{ lang._('Resolver failed for') }}</th>
                <th title="{{ lang._('How long the member has been continuously healthy. DNS returns to it only once this reaches the failback delay.') }}">{{ lang._('Healthy for') }}</th>
                <th>{{ lang._('Last down') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/unboundupstream/service/reconfigure'}) }}
{{ partial('layout_partials/base_dialog', ['fields': resolverForm, 'id': 'DialogResolver',
    'label': lang._('Edit per-member resolver')]) }}
