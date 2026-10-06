{#
 # Copyright (C) 2026 cayossarian (Bill Flood)
 # All rights reserved.
 # BSD 2-Clause License
 #}

<script>
    $(document).ready(function () {
        function plain(s) {
            return $('<textarea/>').html(s === undefined || s === null ? '' : String(s)).val();
        }
        function refreshHolds() {
            ajaxGet('/api/wanfailover/service/holds', {}, function (data) {
                var body = $('#wanfailover-holds tbody').empty();
                if (!data || data.status === 'failed') {
                    body.append($('<tr/>').append($('<td colspan="6"/>').text("{{ lang._('Status unavailable.') }}")));
                    return;
                }
                $.each(data.wans || [], function (i, w) {
                    body.append($('<tr/>')
                        .append($('<td/>').text(plain(w.name)))
                        .append($('<td/>').text(w.held ? "{{ lang._('held') }}" : (w.force_down ? "{{ lang._('forced down (not by this plugin)') }}" : "{{ lang._('in service') }}")))
                        .append($('<td/>').text(plain(w.status)))
                        .append($('<td/>').text(w.loss === null ? '~' : w.loss + ' %'))
                        .append($('<td/>').text(plain(w.judgement || '')))
                        .append($('<td/>').text(w.failback_pending ? "{{ lang._('pending') }}" : '')));
                });
                var notes = [];
                if (data.dry) { notes.push("{{ lang._('Dry run: decisions are logged, nothing is changed.') }}"); }
                $.each(data.unresolved || [], function (i, u) { notes.push("{{ lang._('A selected gateway no longer exists:') }} " + plain(u)); });
                $.each((data.contract || {}).judging || [], function (i, p) { notes.push("{{ lang._('Core changed (all holds released):') }} " + plain(p)); });
                $.each((data.contract || {}).command || [], function (i, p) { notes.push("{{ lang._('Core changed (no new holds):') }} " + plain(p)); });
                $.each((data.contract || {}).tailscale || [], function (i, p) { notes.push("{{ lang._('Tailscale restarts off:') }} " + plain(p)); });
                $('#wanfailover-notes').text(notes.join(' '));
                $('#wanfailover-notes').toggle(notes.length > 0);
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
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/wanfailover/service/reconfigure'}) }}
