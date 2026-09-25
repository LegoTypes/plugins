{#
 # Copyright (C) 2026 cayossarian (Bill Flood)
 # All rights reserved.
 # BSD 2-Clause License
 #}

<style>
    #tunnels-table a.wgct-link { color: inherit; text-decoration: none; border-bottom: 1px dotted currentColor; }
    #tunnels-table a.wgct-link:hover { text-decoration: none; border-bottom-style: solid; }
    #tunnels-table td.wgct-nowrap { white-space: nowrap; }
</style>

<script>
    $(document).ready(function () {
        var links = {
            instance: '/ui/wireguard/general#instances',
            gateways: '/ui/routing/configuration',
            routes: '/ui/routes',
            nat: '/ui/firewall/source_nat',
            groups: '/ui/routing/gateway_groups'
        };

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

        function render(data) {
            var banners = [];
            var tbody = $('<tbody/>');
            if (!data || data.status !== 'ok') {
                var errMsg = data && data.errorMessage
                    ? data.errorMessage
                    : "{{ lang._('The request failed (session expired or the web server is restarting). Reload the page and try again.') }}";
                banners.push($('<div class="alert alert-danger"/>').text(errMsg));
            } else {
                $.each(data.global, function (i, f) {
                    banners.push($('<div class="alert alert-warning"/>').text(f.code + ': ' + f.detail + ' — ' + f.fix));
                });
                if (!data.tunnels.length) {
                    tbody.append($('<tr/>').append($('<td colspan="9"/>').text("{{ lang._('No managed tunnels.') }}")));
                }
                $.each(data.tunnels, function (i, t) {
                    var name = $('<td class="wgct-nowrap"/>').append(link(t.name || t.uuid, links.instance));
                    if (t.device) {
                        var ifaceLabel = t.interface_descr || t.interface;
                        name.append($('<br/>'), $('<small class="text-muted"/>').text(t.device + (ifaceLabel ? ' / ' + ifaceLabel : '')));
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
                        $('<td class="wgct-nowrap"/>').text(t.endpoint || '—'),
                        $('<td/>').append(t.bound_wan ? link(t.bound_wan, links.routes) : $('<span/>').text('—')),
                        mtuCell,
                        gwCell(t.gw4, t.gw4_status, t.gw4_status_text, t.held),
                        gwCell(t.gw6, t.gw6_status, t.gw6_status_text, false),
                        $('<td/>').append(nat.length ? link(nat.join('; '), links.nat) : $('<span/>').text('—')),
                        $('<td/>').append(t.groups.length ? link(t.groups.join(', '), links.groups) : $('<span/>').text('—')),
                        findingBadges(t.findings)
                    ));
                });
            }
            $('#tunnel-banners').empty().append(banners);
            $('#tunnels-table tbody').replaceWith(tbody);
        }

        function refresh() {
            ajaxGet('/api/wgipv6gateway/tunnels/search', {}, function (data) { render(data); });
        }

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
        $('#btn-refresh').on('click', refresh);
        refresh();
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#tunnels">{{ lang._('Tunnels') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="tunnels" class="tab-pane fade in active" style="padding: 1em;">
        <p>{{ lang._('Each managed tunnel is assembled from core configuration: its WireGuard instance and peer, the /32 route that binds it to a WAN, the gateways on its interface, outbound NAT and gateway groups. Edit those on their own pages; this list follows. Hover a finding for what it means and where it is fixed.') }}</p>
        <div id="tunnel-banners"></div>
        <button class="btn btn-default" id="btn-refresh"><i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh view') }}</button>
        <table class="table table-striped table-condensed" id="tunnels-table" style="margin-top: 1em;">
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
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="settings" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
</div>
<section class="page-content-main">
    <div class="content-box">
        <div class="col-md-12">
            <br/>
            <button class="btn btn-primary" id="reconfigureAct"
                    data-endpoint="/api/wgipv6gateway/service/reconfigure"
                    data-label="{{ lang._('Apply') }}"
                    data-error-title="{{ lang._('Error reconfiguring the WireGuard IPv6 gateway') }}"
                    type="button"></button>
            <br/><br/>
        </div>
    </div>
</section>
