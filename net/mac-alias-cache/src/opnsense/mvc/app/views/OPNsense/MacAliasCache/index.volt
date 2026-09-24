<script>
    $(document).ready(function () {
        var flushing = false;

        function fmtAge(s) {
            if (s === null || s === undefined) return '—';
            if (s < 120) return s + ' s';
            if (s < 7200) return Math.round(s / 60) + ' min';
            return (s / 3600).toFixed(1) + ' h';
        }

        function banner(kind, text) {
            $('#banners').append($('<div class="alert"/>').addClass('alert-' + kind).text(text));
        }

        var requestFailed = "{{ lang._('The request failed (session expired or the web server is restarting). Reload the page and try again.') }}";

        function errorText(data) {
            var map = {
                busy: "{{ lang._('The alias update lock is busy (a refresh is running). Try again in a moment.') }}",
                too_soon: "{{ lang._('A flush ran less than 10 seconds ago.') }}",
                hosts_unavailable: "{{ lang._('The host list could not be read (host discovery unavailable); nothing was changed.') }}",
                backend: "{{ lang._('The backend returned an unexpected response:') }} ",
            };
            return (map[data.error] || (data.error + ': ')) + (data.detail || '');
        }

        function summaryTable(summary) {
            var t = $('<table class="table table-condensed"/>').append(
                $('<tr/>').append('<th>{{ lang._("Alias") }}</th><th>{{ lang._("Before") }}</th><th>{{ lang._("After") }}</th><th>{{ lang._("Removed") }}</th><th>{{ lang._("Added") }}</th>'));
            $.each(summary, function (i, s) {
                t.append($('<tr/>')
                    .append($('<td/>').text(s.name))
                    .append($('<td/>').text(s.before === null ? '—' : s.before))
                    .append($('<td/>').text(s.after === null ? '—' : s.after))
                    .append($('<td/>').text(s.removed.join(', ') || '—'))
                    .append($('<td/>').text(s.added.join(', ') || '—')));
            });
            return t;
        }

        function render(data) {
            $('#banners').empty();
            $('#last-flush').text('');
            var lastSummary = $('#last-flush-summary').empty();
            var resultShown = $('#result').is(':visible');
            var tbody = $('#aliases tbody').empty();
            // ajaxGet hands over {} when the request itself failed
            if (!data || (!data.error && !Array.isArray(data.aliases))) { banner('danger', requestFailed); return; }
            if (data.error) { banner('danger', errorText(data)); return; }
            if (data.source === null || data.source === undefined) {
                banner('warning', "{{ lang._('The host list could not be read; the current addresses shown may be incomplete.') }}");
            } else if (data.source === 'arp-ndp') {
                banner('warning', "{{ lang._('Host discovery (hostwatch) is not in use; core resolves MAC aliases from the ARP/NDP tables.') }}");
            }
            if (!data.aliases.length) {
                tbody.append($('<tr/>').append($('<td colspan="6"/>').text("{{ lang._('No MAC aliases defined.') }}")));
            }
            $.each(data.aliases, function (i, a) {
                var oldest = null;
                $.each(a.macs, function (j, m) {
                    if (m.cache_age_s !== null && (oldest === null || m.cache_age_s > oldest)) oldest = m.cache_age_s;
                });
                var detail = $('<tr class="mac-detail"/>').hide();
                var cell = $('<td colspan="6"/>');
                $.each(a.macs, function (j, m) {
                    var current = {};
                    $.each(m.current_items, function (k, ip) { current[ip] = true; });
                    var list = $('<ul class="list-unstyled"/>');
                    $.each(m.cache_items, function (k, ip) {
                        var li = $('<li/>').text(ip);
                        if (!current[ip]) li.addClass('text-danger').append(' ' + "{{ lang._('(cached only — removed by a flush)') }}");
                        list.append(li);
                    });
                    $.each(m.current_items, function (k, ip) {
                        if (m.cache_items.indexOf(ip) < 0) list.append($('<li class="text-muted"/>').text(ip + ' ' + "{{ lang._('(current, not yet cached)') }}"));
                    });
                    cell.append($('<strong/>').text(m.mac + ' — ' + "{{ lang._('cache age') }} " + fmtAge(m.cache_age_s)), list);
                });
                if (!a.macs.length) cell.text("{{ lang._('No host currently matches these entries.') }}");
                detail.append(cell);
                var row = $('<tr class="mac-alias" style="cursor:pointer"/>')
                    .append($('<td/>').text(a.name))
                    .append($('<td/>').text(a.entries.join(', ')))
                    .append($('<td/>').text(a.nested_by.join(', ') || '—'))
                    .append($('<td/>').text(a.pf_count === null ? '—' : a.pf_count))
                    .append($('<td/>').text(a.macs.length))
                    .append($('<td/>').text(fmtAge(oldest)))
                    .on('click', function () { detail.toggle(); });
                tbody.append(row, detail);
            });
            if (data.last_flush) {
                $('#last-flush').text("{{ lang._('Last flush:') }} " + new Date(data.last_flush.at * 1000).toLocaleString());
                if (!resultShown && data.last_flush.summary && data.last_flush.summary.length) {
                    lastSummary.append(summaryTable(data.last_flush.summary));
                }
            }
        }

        function renderResult(data) {
            var panel = $('#result').empty().show();
            // ajaxCall hands over the jqXHR (no JSON) when the request itself failed
            if (!data || (!data.error && !data.summary && !data.note)) {
                panel.append($('<div class="alert alert-danger"/>').text(requestFailed));
                return;
            }
            if (data.error) { panel.append($('<div class="alert alert-danger"/>').text(errorText(data))); return; }
            if (data.note) { panel.append($('<div class="alert alert-info"/>').text(data.note)); return; }
            panel.append(summaryTable(data.summary));
            if (data.update_tables && data.update_tables.rc !== 0) {
                panel.append($('<div class="alert alert-warning"/>').text("{{ lang._('update_tables.py reported a problem:') }} " + data.update_tables.output));
            }
            panel.append($('<p class="text-muted"/>').text("{{ lang._('Alias refreshes requested while the flush held the lock (cron, filter reload, alias Apply) run at the next minute.') }}"));
        }

        function refresh() {
            ajaxGet('/api/macaliascache/service/status', {}, function (data) { render(data); });
        }

        $('#btn-refresh').on('click', refresh);
        $('#btn-flush').on('click', function () {
            if (flushing) return;
            var btn = $(this);
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_DANGER,
                title: "{{ lang._('MAC Alias Cache') }}",
                message: "{{ lang._('Rebuild all MAC aliases and the aliases nesting them from current host discovery data? Addresses no longer reported will be removed from firewall rules.') }}",
                buttons: [{
                    label: "{{ lang._('No') }}",
                    action: function (dialogRef) { dialogRef.close(); }
                }, {
                    label: "{{ lang._('Yes') }}",
                    action: function (dialogRef) {
                        if (flushing) return;
                        dialogRef.close();
                        flushing = true;
                        btn.prop('disabled', true);
                        ajaxCall('/api/macaliascache/service/flush', {}, function (data) {
                            flushing = false;
                            btn.prop('disabled', false);
                            renderResult(data);
                            refresh();
                        });
                    }
                }]
            });
        });
        refresh();
    });
</script>

<div class="content-box" style="padding: 1em;">
    <p>{{ lang._('MAC aliases resolve through a cache that keeps the last addresses of a MAC which host discovery no longer reports for up to 12 hours. Flush & rebuild re-reads every MAC alias, and every alias nesting one, from current host discovery data.') }}</p>
    <div id="banners"></div>
    <button class="btn btn-primary" id="btn-flush"><i class="fa fa-recycle fa-fw"></i> {{ lang._('Flush & rebuild') }}</button>
    <button class="btn btn-default" id="btn-refresh"><i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh view') }}</button>
    <span id="last-flush" class="text-muted" style="margin-left: 1em;"></span>
    <div id="last-flush-summary" style="margin-top: 1em;"></div>
    <div id="result" style="display: none; margin-top: 1em;"></div>
    <table class="table table-striped" id="aliases" style="margin-top: 1em;">
        <thead>
            <tr>
                <th>{{ lang._('MAC alias') }}</th>
                <th>{{ lang._('Entries') }}</th>
                <th>{{ lang._('Nested by') }}</th>
                <th>{{ lang._('pf entries') }}</th>
                <th>{{ lang._('Matching MACs') }}</th>
                <th>{{ lang._('Oldest cache age') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>
