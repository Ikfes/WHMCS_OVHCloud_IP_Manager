<?php

if ( ( "cli" === php_sapi_name() OR ( ! empty( $GLOBALS["file"] ) && preg_match( '/admin\/update\.php$/', $GLOBALS["file"] ) ) ) ) {
    return;
}

require_once __DIR__ . '/lib/common.php';

add_hook( 'ClientAreaFooterOutput', 1, function ( $params ) {
    // make sure current user is authorized and we're on product details page
    if ( empty( $_SESSION['uid'] ) OR empty( $_GET['action'] ) OR 'productdetails' !== $_GET['action'] OR empty( $_GET['id'] ) ) {
        return;
    }
    // make sure module is enabled
    $config = _ovh_ip_manager_get_option();
    if ( empty( $config['enabled'] ) ) {
        return;
    }

    $service_id = $_GET['id'];

    $ip = _ovh_ip_manager_get_service_ip( $service_id );

    $ipBlock = _ovh_ip_manager_get_ip_block( $ip );

    if ( ! $ipBlock ) {
        return;
    }

    // return '<!-- ' . print_r($result['products']['product'][0], true) . ' -->';
    return <<<EOF
<style>
    .table-danger > td {
        background-color: #f5c6cb;
    }
    .table-success > td {
        background-color: #8fd19e;
    }
</style>
<script>
var service_id = $service_id;
var ajaxurl = '{$params['systemurl']}';
</script>
<script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
<!--<script src="https://unpkg.com/popper.js"></script>
<script src="{$params['systemurl']}modules/addons/ovh_ip_manager/templates/js/bootstrap.min.js"></script>-->
<script src="{$params['systemurl']}modules/addons/ovh_ip_manager/templates/js/app.js"></script>

<script type="text/x-template" id="ovh-ip-manager-template">
    <table class="table table-hover">
        <thead>
            <tr>
                <th>IP</th>
                <th>Reverse DNS</th>
                <th>Permanent Mitigation</th>
                <th>Network Firewall</th>
                <th>Game Firewall</th>
                <th>Mitigation alerts</th>
            </tr>
        </thead>
        <tbody>
            <template v-if="ip_addresses.length > 0">
                <tr v-for="item in ip_addresses">
                    <td>{{item.ip}}</td>
                    <td>
                        <span v-if="! editing_reverse_dns" style="display: inline-block">{{item.reverse_dns}} <a @click.prevent="edit_reverse_dns(item)" href="#"><i class="fa fa-edit"></i></a></span>
                        <span v-if="editing_reverse_dns" style="display: inline-block">
                            <input type="text" v-model.trim="item.edited_reverse_dns" style="color: #333" /> 
                            <a @click.prevent="save_reverse_dns(item)" title="Save" href="#"><i class="fa fa-save"></i></a>
                            &nbsp; <a @click.prevent="editing_reverse_dns = false" title="Cancel" href="#"><i class="fa fa-times-circle"></i></a>
                        </span>
                    </td>
                    <td class="text-center text-nowrap">
                        <span v-if="item.mitigation" style="display: inline-block">
                            <span class="badge" style="background-color: #5cb85c;">Enabled</span>&nbsp;
                            <a v-if="!updating_mitigation" @click.prevent="change_mitigation(item)" href="#" title="Disable permanent mitigation"><i style="color: #333;" class="fa fa-power-off"></i></a>
                        </span>
                        <span v-else>
                            <span class="badge" style="background-color: #333;">Disabled</span>&nbsp;
                            <a v-if="!updating_mitigation" @click.prevent="change_mitigation(item)" href="#" title="Enable permanent mitigation"><i style="color: #5cb85c;" class="fa fa-power-off"></i></a>
                        </span>
                        <i v-if="updating_mitigation" class="fa fa-spinner fa-spin"></i>
                     </td>
                    <td><a @click.prevent="manage_network_firewall(item)" href="#" class="btn btn-default">Show</a></td>
                    <td>
                        <a v-if="item.game_ddos_available" @click.prevent="manage_game_firewall(item)" href="#" class="btn btn-default">Show</a>
                        <span v-else>N/A</span>
                    </td>
                    <td>
                        <label><input type="checkbox" v-model="item.notif_email" @change="change_mitigation_alert(item, 'email')" /> Emails<br /></label>
                        <label><input type="checkbox" v-model="item.notif_discord" @change="change_mitigation_alert(item, 'discord')" /> Discord</label>
                       
                        <i v-if="changing_mitigation_alert" class="fa fa-spinner fa-spin"></i>
                    </td>
                </tr>
            </template>
            <tr v-else-if="loading">
                <td colspan="6"><i class="fa fa-spinner fa-spin"></i> loading...</td>
            </tr>
            <tr v-else>
                <td colspan="6">No IP addresses found</td>
            </tr>
        </tbody>
        <tfoot>
            <tr v-if="reverse_dns_error != ''">
                <td colspan="5"><p class="alert alert-danger">{{reverse_dns_error}}</p></td>
            </tr>
            <tr>
                <td colspan="6">
                    <form class="form-inline">
                          <label class="my-1 mr-2" for="discord-webhook-url">Discord Webhook URL:</label>
                          <input style="width: 300px;" type="text" class="form-control mb-2 mr-sm-2" id="discord-webhook-url" v-model="discord_webhook_url">                        
                          <button :disabled="saving_discord_webhook_url" @click="saveDiscordWebhookURL" type="button" class="btn btn-primary mb-2">
                          Save <i v-if="saving_discord_webhook_url" class="fa fa-spinner fa-spin"></i>
                          </button>
                    </form>
                </td>
            </tr>
        </tfoot>
    </table>
    
<div class="modal fade" id="ovh-ip-manager-template-modal-network-firewall" tabindex="-1" role="dialog" aria-labelledby="ovh-ip-manager-template-modal-network-firewall" aria-hidden="true">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Network Firewall Rules for IP {{firewall_ip}}: <a @click.prevent="load_network_firewall_rules" href="#"><i class="fa fa-sync"></i></a></h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <p><strong>Firewall Enabled:</strong> <input v-model="network_firewall_enabled" type="checkbox" style="vertical-align: top"> <i v-if="updating_firewall_status" class="fa fa-spinner fa-spin"></i></p>
                <table class="table table-responsive">
                    <thead>
                    <tr>
                        <th>Sequence</th>
                        <th width="14%">Action</th>
                        <th width="14%">Protocol</th>
                        <th>Destination Port</th>
                        <th>Source</th>
                        <th>Source Port</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr v-if="loading_firewall_rules">
                        <td colspan="7"><i class="fa fa-spinner fa-spin"></i> loading rules...</td>
                    </tr>
                    <template v-else-if="firewall_rules.length">
                        <template v-for="rule in firewall_rules">
                            <tr v-if="rule.sequence">
                                <td>{{rule.sequence}}</td>
                                <td>{{rule.action | uppercase}}</td>
                                <td>
                                    {{rule.protocol | uppercase}}
                                    <br v-if="rule.fragments || rule.tcpOption" />
                                    <small v-if="rule.fragments">fragments</small>
                                    <small v-if="rule.fragments && rule.tcpOption">&mdash;</small>
                                    <small v-if="rule.tcpOption">tcp option: {{rule.tcpOption}}</small>
                                </td>
                                <td>{{rule.destinationPort | stripLeadingEq}}</td>
                                <td>{{rule.source}}</td>
                                <td>{{rule.sourcePort | stripLeadingEq}}</td>
                                <td><a @click.prevent="delete_firewall_rule(rule)" href="#"><i title="Delete this rule" class="fa fa-trash"></i></a></td>
                            </tr>
                        </template>
                    </template>
                    <tr v-else>
                        <td colspan="7">No rules found</td>
                    </tr>
                    </tbody>
                    <tfoot>
                    <tr>
                        <td>
                            <select v-model="network_firewall_rule.sequence" class="form-control">
                                <option v-for="index in 19" :value="index">{{index}}</option>
                            </select>
                        </td>
                        <td>
                            <select v-model="network_firewall_rule.action" class="form-control">
                                <option value="deny">Deny</option>
                                <option value="permit">Permit</option>
                            </select>
                        </td>
                        <td width="22%;">
                            <div style="display: flex; flex-direction: row; justify-content: center; align-items: center;">
                                <select v-model="network_firewall_rule.protocol" class="form-control">
                                    <option value="ah">AH</option>
                                    <option value="esp">ESP</option>
                                    <option value="gre">GRE</option>
                                    <option value="icmp">ICMP</option>
                                    <option value="ipv4">IPv4</option>
                                    <option value="tcp">TCP</option>
                                    <option value="udp">UDP</option>
                                </select>
                                <a @click.prevent="editing_tcp_options = ! editing_tcp_options" v-if="network_firewall_rule.protocol == 'tcp'" href="" title="edit TCP options" style="display: inline-block; margin-left: 4px;"><i class="fa fa-cog"></i></a>
                            </div>
                            <div v-if="editing_tcp_options">
                                <fieldset>
                                    <p style="font-size: 14; margin-top: 10px; margin-bottom: 6px">TCP OPTIONS</p>
                                    <div class="form-check">
                                      <input v-model="tcp_fragments" class="form-check-input" type="checkbox" value="" id="tcp_fragments">
                                      <label class="form-check-label" for="tcp_fragments">Fragments</label>
                                    </div>
                                    
                                    <p style="font-size: 12px;">Flags:</p>
                                    <div class="form-check">
                                      <input v-model="tcp_flag" class="form-check-input" type="radio" name="tcp_flag" id="tcp_flag_none" value="none" checked>
                                      <label class="form-check-label" for="tcp_flag_none">None</label>
                                    </div>
                                    <div class="form-check">
                                      <input v-model="tcp_flag" class="form-check-input" type="radio" name="tcp_flag" id="tcp_flag_established" value="established">
                                      <label class="form-check-label" for="tcp_flag_established">Established</label>
                                    </div>
                                    <div class="form-check">
                                      <input v-model="tcp_flag" class="form-check-input" type="radio" name="tcp_flag" id="tcp_flag_syn" value="syn">
                                      <label class="form-check-label" for="tcp_flag_syn">SYN</label>
                                    </div>
                                </fieldset>
                            </div>
                        </td>
                        <td><input v-model="network_firewall_rule.destinationPort" :disabled="network_firewall_rule.protocol != 'tcp' && network_firewall_rule.protocol != 'udp'" class="form-control" type="number" step="1" min="0"></td>
                        <td><input v-model="network_firewall_rule.source" class="form-control" type="text" placeholder="Default: any port"></td>
                        <td><input v-model="network_firewall_rule.sourcePort" :disabled="network_firewall_rule.protocol != 'tcp' && network_firewall_rule.protocol != 'udp'" class="form-control" type="number" step="1" min="0"></td>
                        <td><a @click.prevent="add_network_firewall_rule" :disabled="loading_firewall_rules" href="#" class="btn btn-success"><i title="Add this rule" class="fa fa-plus-circle"></i> add</a></td>
                    </tr>
                    <tr v-if="error != ''">
                        <td colspan="7"><p class="alert alert-danger">{{error}}</p></td>
                    </tr>
                    </tfoot>
                </table>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="ovh-ip-manager-template-modal-game-firewall" tabindex="-1" role="dialog" aria-labelledby="ovh-ip-manager-template-modal-game-firewall" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Game firewall information for IP {{firewall_ip}}: <a @click.prevent="load_game_firewall_rules" href="#"><i class="fa fa-sync"></i></a></h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <p><strong>Game Firewall Enabled:</strong> <input v-model="game_firewall_enabled" type="checkbox" style="vertical-align: top"> <i v-if="updating_firewall_status" class="fa fa-spinner fa-spin"></i></p>
                <table class="table table-responsive">
                    <thead>
                    <tr>
                        <th>Protocol</th>
                        <th>Ports</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr v-if="loading_firewall_rules">
                        <td colspan="3"><i class="fa fa-spinner fa-spin"></i> loading rules...</td>
                    </tr>
                    <template v-else-if="firewall_rules.length">
                        <template v-for="rule in firewall_rules">
                            <tr v-if="rule.ports" :class="{ 'table-danger': rule.state == 'deleteRulePending', 'table-success': rule.state == 'createRulePending' }">
                                <td>{{rule.protocol}}</td>
                                <td>{{rule.ports.from}} &ndash; {{rule.ports.to}}</td>
                                <td><a @click.prevent="delete_game_firewall_rule(rule)" href="#"><i title="Delete this rule" class="fa fa-trash"></i></a></td>
                            </tr>
                        </template>
                    </template>
                    <tr v-else>
                        <td colspan="3">No rules found</td>
                    </tr>
                    </tbody>
                    <tfoot>
                    <tr>
                        <td>
                            <select v-model="game_firewall_rule.protocol" class="form-control">
                                <option value="arkSurvivalEvolved">arkSurvivalEvolved</option>
                                <option value="arma">arma</option>
                                <option value="gtaMultiTheftAutoSanAndreas">gtaMultiTheftAutoSanAndreas</option>
                                <option value="gtaSanAndreasMultiplayerMod">gtaSanAndreasMultiplayerMod</option>
                                <option value="hl2Source">hl2Source</option>
                                <option value="minecraftPocketEdition">minecraftPocketEdition</option>
                                <option value="minecraftQuery">minecraftQuery</option>
                                <option value="mumble">mumble</option>
                                <option value="other">other</option>
                                <option value="rust">rust</option>
                                <option value="teamspeak2">teamspeak2</option>
                                <option value="teamspeak3">teamspeak3</option>
                                <option value="trackmaniaShootmania">trackmaniaShootmania</option>
                            </select>
                        </td>
                        <td>
                            <input v-model="game_firewall_rule.ports.from" style="width: 36%" type="number" step="1" min="0" placeholder="From port"> &mdash;
                            <input v-model="game_firewall_rule.ports.to" style="width: 36%" type="number" step="1" min="0" placeholder="To port">
                        </td>
                        <td><a @click.prevent="add_game_firewall_rule" :disabled="loading_firewall_rules" href="#" class="btn btn-success"><i title="Add this rule" class="fa fa-plus-circle"></i> add</a></td>
                    </tr>
                    <tr v-if="error != ''">
                        <td colspan="7"><p class="alert alert-danger">{{error}}</p></td>
                    </tr>
                    </tfoot>
                </table>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

</script>


EOF;

} );

