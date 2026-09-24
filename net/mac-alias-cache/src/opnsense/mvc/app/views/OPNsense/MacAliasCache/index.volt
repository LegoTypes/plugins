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
            return $('<div class="alert"/>').addClass('alert-' + kind).text(text);
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
            var thead = $('<thead/>').append($('<tr/>').append(
                $('<th/>').text("{{ lang._('Alias') }}"),
                $('<th/>').text("{{ lang._('Before') }}"),
                $('<th/>').text("{{ lang._('After') }}"),
                $('<th/>').text("{{ lang._('Removed') }}"),
                $('<th/>').text("{{ lang._('Added') }}")));
            var tbody = $('<tbody/>');
            $.each(summary, function (i, s) {
                tbody.append($('<tr/>')
                    .append($('<td/>').text(s.name))
                    .append($('<td/>').text(s.before === null ? '—' : s.before))
                    .append($('<td/>').text(s.after === null ? '—' : s.after))
                    .append($('<td/>').text(s.removed.join(', ') || '—'))
                    .append($('<td/>').text(s.added.join(', ') || '—')));
            });
            return $('<table class="table table-striped table-condensed"/>').append(thead, tbody);
        }

        function summaryHeading(text) {
            return $('<p/>').append($('<strong/>').text(text));
        }

        function summaryTotals(summary) {
            var removed = 0, added = 0, changed = 0;
            $.each(summary, function (i, s) {
                removed += s.removed.length;
                added += s.added.length;
                if (s.removed.length || s.added.length) changed++;
            });
            return { removed: removed, added: added, changed: changed };
        }

        function resultHeadingText(totals) {
            if (totals.removed === 0 && totals.added === 0) {
                return "{{ lang._('Result of this flush') }}: {{ lang._('nothing changed') }}";
            }
            var parts = [];
            if (totals.removed > 0) {
                var addr = totals.removed === 1 ? "{{ lang._('address') }}" : "{{ lang._('addresses') }}";
                parts.push("{{ lang._('removed') }} " + totals.removed + " " + addr);
            }
            if (totals.added > 0) {
                var addr = totals.added === 1 ? "{{ lang._('address') }}" : "{{ lang._('addresses') }}";
                parts.push("{{ lang._('added') }} " + totals.added + " " + addr);
            }
            var alias = totals.changed === 1 ? "{{ lang._('alias') }}" : "{{ lang._('aliases') }}";
            return "{{ lang._('Result of this flush') }}: " + parts.join(", ") + " {{ lang._('across') }} " + totals.changed + " " + alias;
        }

        function render(data) {
            var banners = [];
            var resultShown = $('#result').is(':visible');
            var lastFlushText = '';
            var lastSummaryBuilt = [];
            var tbody = $('<tbody/>');

            // ajaxGet hands over {} when the request itself failed
            if (!data || (!data.error && !Array.isArray(data.aliases))) {
                banners.push(banner('danger', requestFailed));
            } else if (data.error) {
                banners.push(banner('danger', errorText(data)));
            } else {
                if (data.source === null || data.source === undefined) {
                    banners.push(banner('warning', "{{ lang._('The host list could not be read; the current addresses shown may be incomplete.') }}"));
                } else if (data.source === 'arp-ndp') {
                    banners.push(banner('warning', "{{ lang._('Host discovery (hostwatch) is not in use; core resolves MAC aliases from the ARP/NDP tables.') }}"));
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
                    lastFlushText = "{{ lang._('Last flush:') }} " + new Date(data.last_flush.at * 1000).toLocaleString();
                    if (!resultShown && data.last_flush.summary && data.last_flush.summary.length) {
                        lastSummaryBuilt.push(summaryHeading("{{ lang._('Last flush result') }}"), summaryTable(data.last_flush.summary));
                    }
                }
            }

            $('#banners').empty().append(banners);
            $('#last-flush').text(lastFlushText);
            $('#last-flush-summary').empty().append(lastSummaryBuilt);
            $('#aliases tbody').replaceWith(tbody);
        }

        function renderResult(data) {
            var built = [];
            // ajaxCall hands over the jqXHR (no JSON) when the request itself failed
            if (!data || (!data.error && !data.summary && !data.note)) {
                built.push($('<div class="alert alert-danger"/>').text(requestFailed));
            } else if (data.error) {
                built.push($('<div class="alert alert-danger"/>').text(errorText(data)));
            } else if (data.note) {
                built.push($('<div class="alert alert-info"/>').text(data.note));
            } else {
                var totals = summaryTotals(data.summary);
                built.push(summaryHeading(resultHeadingText(totals)));
                built.push(summaryTable(data.summary));
                if (data.update_tables && data.update_tables.rc !== 0) {
                    built.push($('<div class="alert alert-warning"/>').text("{{ lang._('update_tables.py reported a problem:') }} " + data.update_tables.output));
                }
                built.push($('<p class="text-muted"/>').text("{{ lang._('Alias refreshes requested while the flush held the lock (cron, filter reload, alias Apply) run at the next minute.') }}"));
            }
            $('#result').empty().append(built).show();
        }

        function refresh() {
            ajaxGet('/api/macaliascache/service/status', {}, function (data) { render(data); });
        }

        $('#btn-refresh').on('click', refresh);
        $('#btn-flush').on('click', function () {
            if (flushing) return;
            var btn = $(this);
            var label = btn.contents();
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
                        btn.prop('disabled', true).html('<i class="fa fa-spinner fa-pulse fa-fw"></i> {{ lang._("Flushing…") }}');
                        ajaxCall('/api/macaliascache/service/flush', {}, function (data) {
                            flushing = false;
                            btn.prop('disabled', false).empty().append(label);
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
