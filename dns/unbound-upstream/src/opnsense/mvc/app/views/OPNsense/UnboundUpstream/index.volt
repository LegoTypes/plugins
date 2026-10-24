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
        /* the member's reading (section 3.2): only a settled window qualifies it for choice */
        var readings = {
            'settled': "{{ lang._('settled') }}",
            'young': "{{ lang._('young (window not yet full)') }}",
            'cached': "{{ lang._('cached (last reading of the gateway watcher)') }}",
            'none': "{{ lang._('none') }}"
        };
        /* section 3.6c: loaded, verifying (the ruleset changed since the last evaluation) or the named problems; then
           the address the footprint block keeps (spec -04 section 3.2), when there is one */
        function rulesText(data) {
            var r = data.rules || {};
            var text = r.state === 'loaded' ? "{{ lang._('yes') }}"
                : (r.state === 'verifying' ? "{{ lang._('verifying') }}"
                    : "{{ lang._('no') }}" + ((r.problems || []).length ? ': ' + plain(r.problems.join('; ')) : ''));
            if (r.verified_at !== null && r.verified_at !== undefined) {
                text += ' (' + "{{ lang._('verified') }} " + new Date(r.verified_at * 1000).toLocaleString() + ')';
            }
            return text + ', ' + (data.counter_armed && data.blocked !== null
                ? data.blocked + " {{ lang._('blocked packets') }}" : "{{ lang._('counter not armed') }}")
                + (data.footprint ? "; {{ lang._('footprint block for') }} " + plain(data.footprint) : '');
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
                body.append(row("{{ lang._('Resolver route') }}", route.present ? plain((route.reject ? "{{ lang._('reject') }}" : route.gateway + ' ' + route.interface) + ' [' + (route.flags || []).join(' ') + ']' + (route.ours ? '' : " {{ lang._('(not made by this plugin)') }}")) : "{{ lang._('absent') }}"));
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
                $('#unboundupstream-notes').text(notes.join(' ')).toggle(notes.length > 0);
            });
        }

        mapDataToFormUI({'frm_general': '/api/unboundupstream/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                var dfObj = new $.Deferred();
                saveFormToEndpoint('/api/unboundupstream/settings/set', 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function () { refreshState(); }
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
