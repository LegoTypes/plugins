{#
 # Copyright (C) 2026 cayossarian (Bill Flood)
 # All rights reserved.
 # BSD 2-Clause License
 #}

<style>
    .label-up { background-color: #5cb85c; color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
    .label-down { background-color: #d9534f; color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
    .label-na { background-color: #777; color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
    #combined_table { width: 100%; }
    #combined_table th, #combined_table td { padding: 6px 10px; }
</style>

<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_GeneralSettings': '/api/wgipv6gateway/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        // Flag to suppress auto-populate during programmatic form loads
        var suppressAutoPopulate = false;

        // When user picks an IPv4 gateway, auto-populate IPv6 fields
        $(document).on('change', '[id$="gateway.ipv4_gateway"] select', function() {
            if (suppressAutoPopulate) return;
            var uuid = $(this).val();
            if (!uuid) return;
            ajaxGet('/api/wgipv6gateway/settings/resolveWgInfo/' + uuid, {}, function(data) {
                if (!data) return;
                var gwField = $('[id$="gateway.ipv6_gw_address"] input');
                var addrField = $('[id$="gateway.ipv6_address"] input');
                var descField = $('[id$="gateway.description"] input');
                if (data.ipv6_gw_address && gwField.length) {
                    gwField.val(data.ipv6_gw_address);
                }
                if (data.ipv6_address && addrField.length) {
                    addrField.val(data.ipv6_address);
                }
                if (data.description && descField.length && !descField.val()) {
                    descField.val(data.description);
                }
            });
        });

        // Hidden bootgrid for CRUD operations
        var grid = $('#gateway').UIBootgrid({
            search: '/api/wgipv6gateway/settings/searchGateway',
            get: '/api/wgipv6gateway/settings/getGateway/',
            set: '/api/wgipv6gateway/settings/setGateway/',
            add: '/api/wgipv6gateway/settings/addGateway/',
            del: '/api/wgipv6gateway/settings/delGateway/'
        });

        function refreshCombinedTable() {
            ajaxGet('/api/wgipv6gateway/settings/searchGateway', {rowCount: -1, current: 1}, function(configData) {
                ajaxGet('/api/wgipv6gateway/service/status', {}, function(statusData) {
                    var statusMap = {};
                    if (statusData && statusData.gateways) {
                        statusData.gateways.forEach(function(gw) {
                            statusMap[gw.ipv6_address] = gw;
                        });
                    }

                    var rows = (configData && configData.rows) ? configData.rows : [];
                    var html = '';
                    rows.forEach(function(row) {
                        var info = statusMap[row.ipv6_address] || {};
                        var statusLabel = '';
                        if (info.status === 'up') {
                            statusLabel = '<span class="label-up">Up</span>';
                        } else if (info.status === 'down') {
                            statusLabel = '<span class="label-down">Down</span>';
                        } else {
                            statusLabel = '<span class="label-na">N/A</span>';
                        }
                        var enabled = (row.enabled == '1' || row.enabled === true)
                            ? '<i class="fa fa-check-square-o"></i>'
                            : '<i class="fa fa-square-o"></i>';

                        html += '<tr>';
                        html += '<td>' + enabled + '</td>';
                        html += '<td>' + (row.description || '') + '</td>';
                        html += '<td>' + (row.ipv4_gateway || '') + '</td>';
                        html += '<td>' + (info.interface || '') + '</td>';
                        html += '<td>' + (row.ipv6_gw_address || '') + '</td>';
                        html += '<td>' + (row.ipv6_address || '') + '</td>';
                        html += '<td>' + statusLabel + '</td>';
                        html += '<td>';
                        html += '<button class="btn btn-xs btn-default act-edit" data-uuid="' + row.uuid + '" title="Edit"><i class="fa fa-pencil fa-fw"></i></button> ';
                        html += '<button class="btn btn-xs btn-default act-copy" data-uuid="' + row.uuid + '" title="Copy"><i class="fa fa-clone fa-fw"></i></button> ';
                        html += '<button class="btn btn-xs btn-default act-delete" data-uuid="' + row.uuid + '" title="Delete"><i class="fa fa-trash-o fa-fw"></i></button>';
                        html += '</td>';
                        html += '</tr>';
                    });

                    if (rows.length === 0) {
                        html = '<tr><td colspan="8" style="text-align:center;"><em>No gateway mappings configured.</em></td></tr>';
                    }

                    $('#combined_table tbody').html(html);

                    // Bind edit buttons
                    $('.act-edit').on('click', function() {
                        var uuid = $(this).data('uuid');
                        var dialog_id = 'dialog_gateway';
                        suppressAutoPopulate = true;
                        ajaxGet('/api/wgipv6gateway/settings/getGateway/' + uuid, {}, function(data) {
                            suppressAutoPopulate = false;
                            if (data) {
                                setFormData(dialog_id, data);
                                $('#' + dialog_id).modal('show');
                                $('#' + dialog_id + ' .btn-primary').off('click').on('click', function() {
                                    saveFormToEndpoint('/api/wgipv6gateway/settings/setGateway/' + uuid, dialog_id, function() {
                                        $('#' + dialog_id).modal('hide');
                                        refreshCombinedTable();
                                    });
                                });
                            }
                        });
                    });

                    // Bind delete buttons
                    $('.act-delete').on('click', function() {
                        var uuid = $(this).data('uuid');
                        stdDialogConfirm(
                            '{{ lang._("Confirm delete") }}',
                            '{{ lang._("Do you want to delete this gateway mapping?") }}',
                            '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}',
                            function() {
                                ajaxCall('/api/wgipv6gateway/settings/delGateway/' + uuid, {}, function() {
                                    refreshCombinedTable();
                                });
                            }
                        );
                    });

                    // Bind copy buttons
                    $('.act-copy').on('click', function() {
                        var uuid = $(this).data('uuid');
                        ajaxGet('/api/wgipv6gateway/settings/getGateway/' + uuid, {}, function(data) {
                            if (data) {
                                var dialog_id = 'dialog_gateway';
                                setFormData(dialog_id, data);
                                $('#' + dialog_id).modal('show');
                                $('#' + dialog_id + ' .btn-primary').off('click').on('click', function() {
                                    saveFormToEndpoint('/api/wgipv6gateway/settings/addGateway/', dialog_id, function() {
                                        $('#' + dialog_id).modal('hide');
                                        refreshCombinedTable();
                                    });
                                });
                            }
                        });
                    });
                });
            });
        }

        // Initial load
        refreshCombinedTable();

        // Add button
        $('#addGatewayBtn').on('click', function() {
            var dialog_id = 'dialog_gateway';
            suppressAutoPopulate = true;
            ajaxGet('/api/wgipv6gateway/settings/getGateway/', {}, function(data) {
                if (data) {
                    setFormData(dialog_id, data);
                    setTimeout(function() {
                        // Clear all fields for new entry
                        $('[id$="gateway.description"] input').val('');
                        $('[id$="gateway.ipv6_gw_address"] input').val('');
                        $('[id$="gateway.ipv6_address"] input').val('');
                        // Reset dropdown to blank
                        var sel = $('[id$="gateway.ipv4_gateway"] select');
                        sel.val('');
                        sel.selectpicker('refresh');
                        suppressAutoPopulate = false;
                        $('#' + dialog_id).modal('show');
                    }, 100);
                    $('#' + dialog_id + ' .btn-primary').off('click').on('click', function() {
                        saveFormToEndpoint('/api/wgipv6gateway/settings/addGateway/', dialog_id, function() {
                            $('#' + dialog_id).modal('hide');
                            refreshCombinedTable();
                        });
                    });
                }
            });
        });

        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint('/api/wgipv6gateway/settings/set', 'frm_GeneralSettings', function () {
                    dfObj.resolve();
                });
                return dfObj;
            },
            onAction: function (data, status) {
                refreshCombinedTable();
            }
        });
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
</div>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="content-box-header">
        <h3>{{ lang._('IPv6 Gateway Mappings') }}</h3>
    </div>
    <div class="table-responsive">
        <table id="combined_table" class="table table-condensed table-hover table-striped">
            <thead>
                <tr>
                    <th style="width:5em;">{{ lang._('Enabled') }}</th>
                    <th>{{ lang._('Description') }}</th>
                    <th>{{ lang._('IPv4 Gateway') }}</th>
                    <th>{{ lang._('Interface') }}</th>
                    <th>{{ lang._('IPv6 GW Address') }}</th>
                    <th>{{ lang._('IPv6 Address') }}</th>
                    <th style="width:5em;">{{ lang._('Status') }}</th>
                    <th style="width:8em;">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody>
                <tr><td colspan="8" style="text-align:center;"><em>Loading...</em></td></tr>
            </tbody>
        </table>
    </div>
    <div style="padding: 8px 10px;">
        <button id="addGatewayBtn" type="button" class="btn btn-xs btn-primary">
            <span class="fa fa-plus fa-fw"></span>
        </button>
    </div>
</div>

<!-- Hidden bootgrid (needed for UIBootgrid CRUD plumbing) -->
<div style="display:none;">
    {{ partial('layout_partials/base_bootgrid_table', formGridGateway) }}
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogGateway, 'id': formGridGateway['edit_dialog_id'], 'label': lang._('Edit Gateway Mapping')]) }}

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="col-md-12">
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/wgipv6gateway/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error reconfiguring WireGuard IPv6 Gateway') }}"
                type="button">
        </button>
    </div>
</div>
