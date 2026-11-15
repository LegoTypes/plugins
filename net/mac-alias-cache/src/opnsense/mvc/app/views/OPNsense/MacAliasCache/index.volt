<script>
    $(document).ready(function () {
        var flushing = false;

        function fmtAge(s) {
            if (s === null || s === undefined) return '—';
            if (s < 120) return s + ' s';
            if (s < 7200) return Math.round(s / 60) + ' min';
            return (s / 3600).toFixed(1) + ' h';
        }

        /* the exact inverse of core's htmlspecialchars(..., ENT_NOQUOTES): &lt; &gt; and &amp; back, nothing else
           decoded */
        function plain(s) {
            return String(s === undefined || s === null ? '' : s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        }

        function banner(kind, text) {
            return $('<div class="alert"/>').addClass('alert-' + kind).text(text);
        }

        var requestFailed = "{{ lang._('The request failed (session expired or the web server is restarting). Reload the page and try again.') }}";

        function errorText(data) {
            var map = {
                busy: "{{ lang._('Another flush, an alias refresh or the neighbor table update is running. Try again in a moment.') }}",
                too_soon: "{{ lang._('A flush ran less than 10 seconds ago.') }}",
                hosts_unavailable: "{{ lang._('The host list could not be read (host discovery unavailable); nothing was changed.') }}",
                hosts_malformed: "{{ lang._('The host list has no usable rows (no MAC and address in the expected columns); nothing was changed.') }}",
                state_unusable: "{{ lang._('The plugin state or the core MAC alias cache cannot be trusted; nothing was changed.') }}",
                lock_unusable: "{{ lang._('The alias update lock file cannot be used safely; nothing was changed.') }}",
                core_changed: "{{ lang._('The files of core, or an alias name in the applied configuration, no longer match what the plugin expects; nothing was changed.') }}",
                backend: "{{ lang._('The backend returned an unexpected response:') }}",
            };
            return (map[data.error] || (plain(data.error) + ':')) + (data.detail ? ' ' + plain(data.detail) : '');
        }

        // noExpiry: the aliases of this flush that core never rebuilds, each marked in its row
        function summaryTable(summary, noExpiry) {
            var thead = $('<thead/>').append($('<tr/>').append(
                $('<th/>').text("{{ lang._('Alias') }}"),
                $('<th/>').text("{{ lang._('Before') }}"),
                $('<th/>').text("{{ lang._('After') }}"),
                $('<th/>').text("{{ lang._('Removed') }}"),
                $('<th/>').text("{{ lang._('Added') }}")));
            var tbody = $('<tbody/>');
            $.each(summary, function (i, s) {
                var name = $('<td/>').text(s.name);
                if (noExpiry.indexOf(s.name) >= 0) {
                    name.append($('<div class="text-warning"/>').text("{{ lang._('not rebuilt: its lifetime is not above 0') }}"));
                }
                tbody.append($('<tr/>')
                    .append(name)
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

        function sourceText(source) {
            if (source === 'discovery') return "{{ lang._('Host list: host discovery') }}";
            if (source === 'arp-ndp') return "{{ lang._('Host list: ARP and NDP tables (host discovery is off)') }}";
            return "{{ lang._('Host list:') }} " + plain(source);
        }

        // the problems of the neighbor addresses alone, and the two conditions status computes for them, are shown
        // only while the neighbor table is in use: with the setting off or host discovery off the user can do
        // nothing about them. A settings file that cannot be read reads as off, and is the one shown then
        var neighborItems = ['neighbor_merge', 'ndp', 'neighbors_setting', 'neighbors_file', 'neighbors_lock'];

        // the neighbor tick's result once it has been another than ok for ten minutes (status: neighbors.failing)
        var failingText = {
            busy: "{{ lang._('The neighbor table update keeps finding the alias update lock of core held, so it changes nothing.') }}",
            hosts_unavailable: "{{ lang._('The neighbor table update cannot read the host list of host discovery, so it changes nothing.') }}",
            neighbors_unavailable: "{{ lang._('The neighbor table update cannot read the neighbor table, so it changes nothing: ndp fails, runs longer than 5 seconds or lists more than 1 MiB (about 6,000 entries).') }}",
            cache_unreadable: "{{ lang._('The neighbor table update cannot read the MAC alias cache of core safely, so it changes nothing. A flush writes the cache anew.') }}",
            state_unusable: "{{ lang._('The neighbor table update cannot use the state files of the plugin, so it changes nothing.') }}",
            lock_unusable: "{{ lang._('The neighbor table update cannot use the alias update lock of core safely, so it changes nothing.') }}",
            core_changed: "{{ lang._('The neighbor table update no longer finds what it relies on in the files of core, so it changes nothing.') }}",
            internal: "{{ lang._('The neighbor table update ends in an error of its own, so it changes nothing. The system log has the detail.') }}"
        };

        function neighborsInUse(data) {
            var n = data.neighbors || {};
            return (n.enabled === true || n.setting === 'unusable') && data.source === 'discovery';
        }

        function neighborsText(data) {
            var n = data.neighbors;
            if (!n) return '';
            if (!n.enabled) return "{{ lang._('Neighbor table: off (the setting below turns it on)') }}";
            if (data.source === 'arp-ndp') return "{{ lang._('Neighbor table: not used (host discovery is off)') }}";
            if (data.source !== 'discovery') return '';
            return "{{ lang._('Neighbor table: on,') }} " + n.keys + ' ' + (n.keys === 1
                ? "{{ lang._('address added') }}" : "{{ lang._('addresses added') }}");
        }

        function render(data) {
            var banners = [];
            var sourceLine = '';
            var neighborsLine = '';
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
                } else {
                    sourceLine = sourceText(data.source);
                }
                neighborsLine = neighborsText(data);
                var inUse = neighborsInUse(data);
                $.each(data.problems || [], function (i, p) {
                    if (neighborItems.indexOf(p.item) >= 0 && !inUse) return;
                    banners.push(banner(p.blocks_flush ? 'danger' : 'warning', plain(p.problem || p.item)));
                });
                if (data.neighbors && data.neighbors.enabled === true && data.neighbors.failing) {
                    var failing = data.neighbors.failing;
                    banners.push(banner('warning', (failingText[failing.result]
                        || "{{ lang._('The neighbor table update fails, so it changes nothing:') }} " + plain(failing.result) + '.')
                        + " {{ lang._('This has lasted since') }} " + new Date(failing.since * 1000).toLocaleString()
                        + ". {{ lang._('The addresses it added leave the aliases 12 hours after they were last written.') }}"));
                }
                if (inUse && data.neighbors.stale) {
                    banners.push(banner('warning', "{{ lang._('The neighbor table update has not completed a run for over two hours, so the addresses it added leave the aliases 12 hours after they were last written. Check that cron is running, and the problems shown here.') }}"));
                }
                if (inUse && data.neighbors.over_limit > 0) {
                    banners.push(banner('warning', "{{ lang._('The limit of 32 addresses for one MAC and 1024 in all kept addresses of the neighbor table out of the aliases. A MAC with that many addresses is unusual; check the device. Addresses left out:') }} " + data.neighbors.over_limit));
                }
                $.each(data.notes || [], function (i, n) {
                    if (n.shown) {
                        banners.push(banner('info', plain(n.note)));
                    }
                });
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
                            if (!current[ip]) li.addClass('text-danger').append(document.createTextNode(' ' + "{{ lang._('(cached only — removed by a flush)') }}"));
                            list.append(li);
                        });
                        $.each(m.current_items, function (k, ip) {
                            if (m.cache_items.indexOf(ip) < 0) list.append($('<li class="text-muted"/>').text(ip + ' ' + "{{ lang._('(current, not yet cached)') }}"));
                        });
                        $.each(m.neighbor_items || [], function (k, item) {
                            list.append($('<li/>').text(item.ip + ' ' + "{{ lang._('(from the neighbor table)') }}"));
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
                        lastSummaryBuilt.push(summaryHeading("{{ lang._('Last flush result') }}"), summaryTable(data.last_flush.summary, []));
                    }
                }
            }

            $('#banners').empty().append(banners);
            $('#last-flush').text(lastFlushText);
            $('#source').text(sourceLine);
            $('#neighbors').text(neighborsLine);
            $('#last-flush-summary').empty().append(lastSummaryBuilt);
            $('#aliases tbody').replaceWith(tbody);
        }

        function renderResult(data) {
            var built = [];
            // ajaxCall hands over the jqXHR (no JSON) when the request itself failed
            if (!data || (!data.error && !data.errorMessage && !data.summary && !data.note)) {
                built.push($('<div class="alert alert-danger"/>').text(requestFailed));
            } else if (data.error) {
                built.push($('<div class="alert alert-danger"/>').text(errorText(data)));
            } else if (data.errorMessage) {
                built.push($('<div class="alert alert-danger"/>').text(plain(data.errorMessage)));
            } else if (data.note) {
                built.push($('<div class="alert alert-info"/>').text(plain(data.note)));
            } else {
                var totals = summaryTotals(data.summary);
                built.push(summaryHeading(resultHeadingText(totals)));
                built.push(summaryTable(data.summary, data.no_expiry || []));
                if (data.neighbors && data.neighbors.skipped === 'neighbors_unavailable') {
                    built.push(banner('warning', "{{ lang._('The neighbor table could not be read, so its addresses were not added by this flush. The next minute adds them.') }}"));
                }
                if (data.rows_rejected > 0) {
                    built.push($('<div class="alert alert-warning"/>').text(data.rows_rejected === 1
                        ? "{{ lang._('1 host row was ignored (no MAC and address in the expected columns)') }}"
                        : data.rows_rejected + " {{ lang._('host rows were ignored (no MAC and address in the expected columns)') }}"));
                }
                // core's update: its exit status first, then its reply's status, which only an exit status of 0 has
                var update = data.update_tables;
                if (update) {
                    var output = plain(update.output);
                    var messages = plain((update.messages || []).join('; '));
                    if (update.rc !== 0) {
                        built.push(banner('warning', "{{ lang._('update_tables.py reported a problem:') }} " + output));
                    } else if (update.status === null || update.status === undefined) {
                        built.push(banner('warning', "{{ lang._('The update by core printed no reply the plugin could read') }}" + (output ? ': ' + output : '.')));
                    } else if (update.status === 'error') {
                        built.push(banner('warning', "{{ lang._('Core reported an error loading an alias table:') }} " + messages));
                    } else if (update.status !== 'ok') {
                        built.push(banner('warning', "{{ lang._('The update by core answered with the status') }} " + plain(update.status) + (messages ? ': ' + messages : '')));
                    }
                    if (!update.complete) {
                        built.push(banner('warning', "{{ lang._('A table this update left empty was not flushed and keeps its addresses until the next flush.') }}"));
                    }
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
                message: "{{ lang._('Rebuild all MAC aliases and the aliases nesting them from current host discovery data and the neighbor table? Addresses no longer reported will be removed from firewall rules.') }}",
                buttons: [{
                    label: "{{ lang._('No') }}",
                    action: function (dialogRef) { dialogRef.close(); }
                }, {
                    label: "{{ lang._('Yes') }}",
                    action: function (dialogRef) {
                        if (flushing) return;
                        dialogRef.close();
                        flushing = true;
                        btn.prop('disabled', true).empty().append($('<i class="fa fa-spinner fa-pulse fa-fw"/>'),
                            document.createTextNode(' ' + "{{ lang._('Flushing…') }}"));
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
        // reconfigure answers with its tick's reply: busy means another update held a lock, and the next minute's
        // tick makes the change
        function applied(data) {
            var busy = data && data.neighbors && data.neighbors.error === 'busy';
            $('#apply-note').text(busy ? "{{ lang._('The setting is saved. Another update was running, so the change acts within a minute.') }}" : '').toggle(!!busy);
        }

        mapDataToFormUI({'frm_general': '/api/macaliascache/settings/get'});
        // Apply saves the setting, and applies it only once it is saved: the settings file is rendered and one
        // neighbor tick runs, so the page then shows the new state
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                var dfObj = new $.Deferred();
                saveFormToEndpoint('/api/macaliascache/settings/set', 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function (data) {
                applied(data);
                refresh();
            }
        });
        refresh();
    });
</script>

<div class="content-box" style="padding: 1em;">
    <p>{{ lang._('MAC aliases resolve through a cache that keeps the last addresses of a MAC which host discovery no longer reports for up to 12 hours. Flush & rebuild re-reads every MAC alias, and every alias nesting one, from current host discovery data. With the setting below on and host discovery on, the plugin also adds, each minute, the IPv6 addresses the neighbor table has for a listed MAC and host discovery lacks.') }}</p>
    <div id="banners"></div>
    <button class="btn btn-primary" id="btn-flush"><i class="fa fa-recycle fa-fw"></i> {{ lang._('Flush & rebuild') }}</button>
    <button class="btn btn-default" id="btn-refresh"><i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh view') }}</button>
    <span id="last-flush" class="text-muted" style="margin-left: 1em;"></span>
    <span id="source" class="text-muted" style="margin-left: 1em;"></span>
    <span id="neighbors" class="text-muted" style="margin-left: 1em;"></span>
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
<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    <div class="alert alert-info" id="apply-note" style="display: none;"></div>
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/macaliascache/service/reconfigure'}) }}
