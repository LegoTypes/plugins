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
        function failbackText(f) {
            if (!f) { return ''; }
            if (f.state === 'moving') { return "{{ lang._('moving connections back') }}"; }
            var mins = Math.ceil(f.left / 60);
            if (f.state === 'waiting') { return "{{ lang._('pending: waiting for a clean reading, then') }} " + mins + " {{ lang._('min') }}"; }
            return "{{ lang._('pending:') }} " + mins + " {{ lang._('min left') }}";
        }
        function refreshHolds() {
            ajaxGet('/api/wanfailover/service/wan_status', {}, function (data) {
                var body = $('#wanfailover-holds tbody').empty();
                if (!data || data.status === 'failed') {
                    body.append($('<tr/>').append($('<td colspan="6"/>').text("{{ lang._('Status unavailable.') }}")));
                    return;
                }
                $.each(data.wans || [], function (i, w) {
                    body.append($('<tr/>')
                        .append($('<td/>').text(plain(w.name)))
                        .append($('<td/>').text(w.held ? "{{ lang._('held') }}" : (w.simulated ? "{{ lang._('held (dry run, simulated)') }}" : (w.force_down ? "{{ lang._('forced down (not by this plugin)') }}" : "{{ lang._('in service') }}"))))
                        .append($('<td/>').text(plain(w.status)))
                        .append($('<td/>').text(w.loss === null ? '~' : w.loss + ' %'))
                        .append($('<td/>').text(plain(w.judgement || '')))
                        .append($('<td/>').text(failbackText(w.failback))));
                });
                var notes = [];
                if (data.dry) { notes.push("{{ lang._('Dry run: holds are simulated and logged; nothing is held, killed or restarted.') }}"); }
                if (data.enabled && (data.wans || []).length < 2) { notes.push("{{ lang._('Fewer than two WAN gateways selected: nothing can be held.') }}"); }
                if (data.foreign > 0) { notes.push("{{ lang._('A hold record that does not belong to this plugin was ignored; its gateway keeps force_down until it is cleared by hand.') }}"); }
                if (data.state_corrupt) { notes.push("{{ lang._('The runtime state was unreadable and started fresh.') }}"); }
                $.each(data.unresolved || [], function (i, u) { notes.push("{{ lang._('A selected gateway no longer exists:') }} " + plain(u)); });
                $.each(data.wans || [], function (i, w) {
                    if (w.unjudgeable === 'disabled') { notes.push("{{ lang._('%s is disabled: the plugin can never judge it, so it never backs a hold. Enable it under System: Gateways: Configuration, or deselect it.') }}".replace('%s', plain(w.name))); }
                    if (w.unjudgeable === 'monitor_disable') { notes.push("{{ lang._('%s has gateway monitoring disabled: the plugin can never judge it, so it never backs a hold. Enable monitoring under System: Gateways: Configuration, or deselect it.') }}".replace('%s', plain(w.name))); }
                });
                $.each((data.contract || {}).judging || [], function (i, p) { notes.push("{{ lang._('Core changed (no new holds; all holds released if it lasts 3 minutes):') }} " + plain(p)); });
                $.each((data.contract || {}).command || [], function (i, p) { notes.push("{{ lang._('Core changed (no new holds):') }} " + plain(p)); });
                $.each((data.contract || {}).tailscale || [], function (i, p) { notes.push("{{ lang._('Tailscale restarts off:') }} " + plain(p)); });
                $.each((data.contract || {}).removal || [], function (i, p) { notes.push("{{ lang._('Core changed (affects only a package removal when configd does not answer):') }} " + plain(p)); });
                $.each((data.contract || {}).names || [], function (i, p) { notes.push("{{ lang._('Core changed (a gateway name core accepts may read here as unresolved):') }} " + plain(p)); });
                var box = $('#wanfailover-notes').empty();
                $.each(notes, function (i, n) { box.append($('<div/>').text(n)); });
                box.toggle(notes.length > 0);
            });
        }

        mapDataToFormUI({'frm_general': '/api/wanfailover/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                var dfObj = new $.Deferred();
                saveFormToEndpoint('/api/wanfailover/settings/set', 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function () { refreshHolds(); }
        });
        $('#releaseAct').SimpleActionButton({onAction: function () { refreshHolds(); }});
        $('#failbackNowAct').SimpleActionButton({onAction: function () { refreshHolds(); }});
        refreshHolds();
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
</div>
<div class="content-box">
    <div class="alert alert-info" id="wanfailover-notes" style="display: none;"></div>
    <table class="table table-condensed" id="wanfailover-holds">
        <thead>
            <tr>
                <th>{{ lang._('Gateway') }}</th>
                <th>{{ lang._('Held') }}</th>
                <th>{{ lang._('Status') }}</th>
                <th>{{ lang._('Loss') }}</th>
                <th>{{ lang._('Judgement') }}</th>
                <th>{{ lang._('Failback') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
    <button class="btn btn-default" id="releaseAct" data-endpoint="/api/wanfailover/service/release" data-label="{{ lang._('Release holds') }}" type="button"></button>
    <button class="btn btn-default" id="failbackNowAct" data-endpoint="/api/wanfailover/service/failback_now" data-label="{{ lang._('Fail back now') }}" type="button"></button>
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/wanfailover/service/reconfigure'}) }}
