
var ovh_ip_manager = {

    init: function () {
        $( document ).ready( function () {
            ovh_ip_manager.load_ui();
        } );
    },

    load_ui: function () {
        var domain_tab = $( '#tabOverview .nav-tabs > li > a[href="#domain"]' );
        if ( domain_tab.length ) {
            domain_tab.parent().after('<li><a href="#ovh-ip-manager"><i class="fa fa-server"></i> IP Manager</a></li>');
            $( '#tabOverview .product-details-tab-container > #domain' ).after( '<div class="tab-pane" id="ovh-ip-manager">' + ovh_ip_manager.get_template() + '</div>' );

            ovh_ip_manager.load_app();

            $( 'li > a[href="#ovh-ip-manager"]' ).on( 'click', function (e) {
                $('ul.nav-tabs a[href="#ovh-ip-manager"]').tab('show');
            } );
        }
    },

    get_template: function ( ) {
        return $( '#ovh-ip-manager-template' )[0].innerHTML;
    },

    load_app: function () {
        window.app_ovh_ip_manager = new Vue({
            el: '#ovh-ip-manager',
            data: {
                loading: false,
                ip_addresses: [],
                editing_reverse_dns: false,
                updating_mitigation: false,
                network_firewall_enabled: false,
                game_firewall_enabled: false,
                updating_firewall_status: false,
                firewall_ip: '',
                firewall_enabled: false,
                firewall_rules: [],
                loading_firewall_rules: false,
                network_firewall_rule: {
                    sequence: '1',
                    action: 'permit',
                    protocol: 'tcp',
                    destinationPort: '',
                    source: '',
                    sourcePort: ''
                },
                game_firewall_rule: {
                    ports: {
                        from: '',
                        to: ''
                    },
                    protocol: 'other'
                },
                error: '',
                init: '',
                reverse_dns_error: '',
                updating_mitigation_alert: false,
                editing_tcp_options: false,
                tcp_fragments: false,
                tcp_flag: 'none'
            },
            watch: {

                network_firewall_enabled: function () {
                    if ( this.init && ( Date.now()-this.init ) < 1000 ) {
                        this.init = '';
                        return;
                    }
                    this.error = '';
                    this.updating_firewall_status = true;
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'enable_network_firewall',
                            service_id: service_id,
                            ip: this.firewall_ip,
                            enable: this.network_firewall_enabled ? 'yes' : 'no'
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.error = resp.error;
                                context.init = Date.now();
                                context.network_firewall_enabled = ! context.network_firewall_enabled;
                            }
                        },
                        complete: function () {
                            context.updating_firewall_status = false;
                        }
                    });
                },

                game_firewall_enabled: function () {
                    if ( this.init && ( Date.now()-this.init ) < 1000 ) {
                        this.init = '';
                        return;
                    }
                    this.error = '';
                    this.updating_firewall_status = true;
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'enable_game_firewall',
                            service_id: service_id,
                            ip: this.firewall_ip,
                            enable: this.game_firewall_enabled ? 'yes' : 'no'
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.error = resp.error;
                                context.init = Date.now();
                                context.game_firewall_enabled = ! context.game_firewall_enabled;
                            }
                        },
                        complete: function () {
                            context.updating_firewall_status = false;
                        }
                    });
                }

            },
            computed: {

                parsedFirewallRules: function () {
                    var rules = [];
                    for ( var id in this.firewall_rules ) {
                        var rule = this.firewall_rules[ id ];
                        if ( rule.state === 'deleteRulePending' ) {
                            continue;
                        }
                        rules.push(rule);
                    }
                    return rules;
                }

            },
            filters: {

                uppercase: function (value) {
                    if ( value ) {
                        return value.toUpperCase();
                    }
                },

                stripLeadingEq: function (value) {
                    console.log("protocol to parse: " + value);
                    if (  value && /^eq\s+/.test( value.trim() )  ) {
                        value = value.replace(/^eq\s+/, '');
                    }
                    return value;
                }

            },
            methods: {
                load_ips: function ( ) {
                    this.loading = true;
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'get_ips',
                            service_id: service_id
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.ips ) {
                                for ( var i in resp.ips ) {
                                    resp.ips[ i ].edited_reverse_dns = '';
                                }
                                context.ip_addresses = resp.ips;
                            }
                        },
                        complete: function () {

                        }
                    });
                },

                edit_reverse_dns: function (item) {
                    item.edited_reverse_dns = item.reverse_dns;
                    this.editing_reverse_dns = true;
                },

                save_reverse_dns: function (item) {
                    if ( ! item.edited_reverse_dns || '' === item.edited_reverse_dns ) {
                        return;
                    }
                    this.reverse_dns_error = '';
                    this.editing_reverse_dns = false;

                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'save_reverse_dns',
                            service_id: service_id,
                            ip: item.ip,
                            domain: item.edited_reverse_dns
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.reverse_dns_error = resp.error;
                            }
                            else {
                                item.reverse_dns = item.edited_reverse_dns;
                                item.edited_reverse_dns = '';
                            }
                        },
                        complete: function () {

                        }
                    });
                },

                change_mitigation: function (item) {
                    var context = this;
                    this.updating_mitigation = true;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'change_mitigation',
                            service_id: service_id,
                            ip: item.ip,
                            enable: ( item.mitigation ? 'no' : 'yes' )
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( typeof resp.enabled !== "undefined" ) {
                                item.mitigation = resp.enabled;
                            }
                        },
                        complete: function () {
                            context.updating_mitigation = false;
                        }
                    });
                },

                manage_network_firewall: function (item) {
                    this.firewall_ip = item.ip;
                    this.load_network_firewall_rules();
                    $('#ovh-ip-manager-template-modal-network-firewall').modal('show');
                },

                load_network_firewall_rules: function () {
                    var context = this;
                    this.firewall_rules = [];
                    this.loading_firewall_rules = true;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'get_network_firewall_rules',
                            service_id: service_id,
                            ip: this.firewall_ip
                        },
                        success: function (resp) {
                            console.log(resp);
                            context.init = Date.now();
                            if ( resp.rules ) {
                                context.firewall_rules = resp.rules;
                            }
                            if ( typeof resp.firewall_enabled !== "undefined" ) {
                                context.network_firewall_enabled = resp.firewall_enabled;
                            }
                        },
                        complete: function () {
                            context.loading_firewall_rules = false;
                        }
                    });
                },

                add_network_firewall_rule: function () {
                    this.error = '';
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'add_network_firewall_rule',
                            service_id: service_id,
                            ip: this.firewall_ip,
                            sequence: this.network_firewall_rule.sequence,
                            operation: this.network_firewall_rule.action,
                            protocol: this.network_firewall_rule.protocol,
                            destinationPort: this.network_firewall_rule.destinationPort,
                            source: this.network_firewall_rule.source,
                            sourcePort: this.network_firewall_rule.sourcePort,
                            fragments: this.tcp_fragments ? "yes" : "no",
                            flags: this.tcp_flag
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.error = resp.error;
                            }
                            else {
                                if ( context.network_firewall_rule.protocol === 'tcp' ) {
                                    context.tcp_fragments = false;
                                    context.tcp_flag = 'none';
                                }

                                context.network_firewall_rule.sequence = '1';
                                context.network_firewall_rule.action = 'permit';
                                context.network_firewall_rule.protocol = 'tcp';
                                context.network_firewall_rule.destinationPort = '';
                                context.network_firewall_rule.source = '';
                                context.network_firewall_rule.sourcePort = '';

                                context.load_network_firewall_rules();
                            }
                        },
                        complete: function () {

                        }
                    });
                },

                delete_firewall_rule: function (rule) {
                    if ( ! confirm( "Are you sure that you want to delete this rule?" ) ) {
                        return;
                    }
                    this.error = '';
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'delete_network_firewall_rule',
                            service_id: service_id,
                            ip: this.firewall_ip,
                            sequence: rule.sequence
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.error = resp.error;
                            }
                            else {
                                context.load_network_firewall_rules();
                            }
                        },
                        complete: function () {

                        }
                    });
                },

                manage_game_firewall: function (item) {
                    this.firewall_ip = item.ip;
                    this.load_game_firewall_rules();
                    $('#ovh-ip-manager-template-modal-game-firewall').modal('show');
                },

                load_game_firewall_rules: function () {
                    this.error = '';
                    var context = this;
                    this.firewall_rules = [];
                    this.loading_firewall_rules = true;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'get_game_firewall_rules',
                            service_id: service_id,
                            ip: this.firewall_ip
                        },
                        success: function (resp) {
                            console.log(resp);
                            context.init = Date.now();
                            if ( resp.rules ) {
                                context.firewall_rules = resp.rules;
                            }
                            if ( typeof resp.firewall_enabled !== "undefined" ) {
                                context.game_firewall_enabled = resp.firewall_enabled;
                            }
                        },
                        complete: function () {
                            context.loading_firewall_rules = false;
                        }
                    });
                },

                add_game_firewall_rule: function () {
                    this.error = '';
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'add_game_firewall_rule',
                            service_id: service_id,
                            ip: this.firewall_ip,
                            protocol: this.game_firewall_rule.protocol,
                            fromPort: this.game_firewall_rule.ports.from,
                            toPort: this.game_firewall_rule.ports.to,
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.error = resp.error;
                            }
                            else {
                                context.game_firewall_rule.protocol = 'other';
                                context.game_firewall_rule.ports.from = '';
                                context.game_firewall_rule.ports.to = '';

                                context.load_game_firewall_rules();
                            }
                        },
                        complete: function () {

                        }
                    });
                },

                delete_game_firewall_rule: function (rule) {
                    if ( ! confirm( "Are you sure that you want to delete this rule?" ) ) {
                        return;
                    }
                    this.error = '';
                    var context = this;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'delete_game_firewall_rule',
                            service_id: service_id,
                            ip: this.firewall_ip,
                            id: rule.id
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( resp.error ) {
                                context.error = resp.error;
                            }
                            else {
                                context.load_game_firewall_rules();
                            }
                        },
                        complete: function () {

                        }
                    });
                },

                change_mitigation_alert: function (item, notif_type) {
                    console.log(notif_type);
                    console.log(item);
                    /*var context = this;
                    this.updating_mitigation_alert = true;
                    $.ajax({
                        url: ajaxurl + '/modules/addons/ovh_ip_manager/ajax.php',
                        type: 'POST',
                        data: {
                            action: 'change_mitigation_alert',
                            service_id: service_id,
                            ip: item.ip,
                            enable: ( item['notif_'] + notif_type ? 'no' : 'yes' ),
                            notif_type
                        },
                        success: function (resp) {
                            console.log(resp);
                            if ( typeof resp.done !== "undefined" ) {
                                item['notif_' + notif_type] = item['notif_' + notif_type];
                            }
                        },
                        complete: function () {
                            context.updating_mitigation_alert = false;
                        }
                    });*/
                },

            },
            created: function () {
                this.load_ips();
                console.log("Ready");
            }
        });
    }

};

ovh_ip_manager.init();


