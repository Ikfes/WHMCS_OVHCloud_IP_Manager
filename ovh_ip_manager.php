<?php
use WHMCS\Database\Capsule;

if ( ! defined( 'WHMCS' ) ) {
    die('Access to this file outside WHMCS is restricted.');
}

function ovh_ip_manager_config( ){
    $url  = Capsule::table('tblconfiguration')->where('setting','SystemURL')->first();

    $config = array(
        'name'          => 'OVH IP Manager',
        'description'   => 'Make IP management available to clients. Management includes firewall rules editing.',
        'version'       => '1.0.1',
        'author'        => 'Stephane',
        'fields'        => array(
            'enabled'       => array(
                'FriendlyName'  => 'Enable',
                'Type'          => 'yesno',
                'Description'   => 'Enable OVH IP Manager',
            ),
            'app_key'       => array(
                'FriendlyName'  => 'Application Key',
                'Type'          => 'text',
                'Description'   => 'Find your credentials here: https://eu.api.ovh.com/createApp/',
                'Default'       => '',
            ),
            'secret_key'    => array(
                'FriendlyName'  => 'Secret Key',
                'Type'          => 'text',
                'Description'   => 'Find your credentials here: https://eu.api.ovh.com/createApp/',
                'Default'       => '',
            ),
            'consumer_key'  => array(
                'FriendlyName'  => 'Consumer Key',
                'Type'          => 'text',
                'Description'   => <<<EOF
Find your credentials here: https://eu.api.ovh.com/createApp/
<div style="width: 100%; margin-top: 10px" class="cron-command input-group">
    <span class="input-group-addon" id="cronPhp">Cron Command</span>
    <input type="text" value="*/5 * * * * /usr/bin/wget -O /dev/null {$url->value}modules/addons/ovh_ip_manager/cron.php" class="form-control" onfocus="this.select()" onmouseup="return false;">
</div>
EOF,
                'Default'       => '',
            ),
        ),
        'language'      => 'english',
    );

    return $config;
}

function ovh_ip_manager_activate( ) {
    $queries[] = <<<EOF
CREATE TABLE mod_ovh_ip_manager_mitigation_alerts (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  customer_id bigint(20) UNSIGNED NOT NULL,
  ip_address varchar(16) NOT NULL,
  ip_block varchar(40) NOT NULL,
  service_id bigint(20) UNSIGNED NOT NULL,
  mitigation_at datetime NOT NULL,
  alert_sent_at datetime NOT NULL,
  notif_email tinyint(1) NOT NULL DEFAULT 1,
  notif_discord tinyint(1) NOT NULL DEFAULT 0,
  created_at datetime NOT NULL,
  updated_at datetime NULL,
  processed_at datetime NULL,
  PRIMARY KEY  (id),
  KEY customer_id (customer_id),
  KEY ip_address (ip_address)
);
EOF;
    $queries[] = <<<EOF
CREATE TABLE mod_ovh_ip_manager_game_ddos_status (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  customer_id bigint(20) UNSIGNED NOT NULL,
  ip_address varchar(16) NOT NULL,
  ip_block varchar(40) NOT NULL,
  service_id bigint(20) UNSIGNED NOT NULL,
  available tinyint(1) NOT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NULL,
  PRIMARY KEY  (id),
  KEY customer_id (customer_id),
  KEY ip_address (ip_address)
);
EOF;
    $queries[] = <<<EOF
CREATE TABLE mod_ovh_ip_manager_customer_options (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  customer_id bigint(20) UNSIGNED NOT NULL,
  option_name varchar(255) NOT NULL,
  option_value TEXT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NULL,
  PRIMARY KEY  (id),
  KEY customer_id (customer_id),
  KEY option_name (option_name)
);
EOF;

    foreach ( $queries as $query ) {
        full_query( $query );
    }

    // auto-mitigation active alert
    $template = Capsule::table( 'tblemailtemplates' )->where( 'name', 'OVH auto mitigation enabled' )->first();
    if ( ! $template ) {
        Capsule::table( 'tblemailtemplates' )->insert( array(
            'type'          => 'product',
            'name'          => 'OVH auto mitigation enabled',
            'subject'       => 'Auto-mitigation enabled',
            'message'       => <<<EOF
<p>
Dear {\$client_name}, 
</p>
<p>
This message is to confirm that your server {\$service_dedicated_ip} is under mitigation procedure to contain a possible attack we have automatically detected. 
You'll receive another alert when this procedure is lifted.
</p>
<p>
This alert was sent because you've opted to receive auto-mitigation alerts. You can disable this notification at any time
in your client area at <a href="{\$whmcs_url}">{\$whmcs_url}</a>. 
</p>
EOF,
            'created_at'    => date('Y-m-d H:i:s'),
        ) );
    }

    // auto-mitigation inactive alert
    $template = Capsule::table( 'tblemailtemplates' )->where( 'name', 'OVH auto mitigation disabled' )->first();
    if ( ! $template ) {
        Capsule::table( 'tblemailtemplates' )->insert( array(
            'type'          => 'product',
            'name'          => 'OVH auto mitigation disabled',
            'subject'       => 'Auto-mitigation disabled',
            'message'       => <<<EOF
<p>
Dear {\$client_name}, 
</p>
<p>
This message is to confirm that the auto-mitigation procedure on your server {\$service_dedicated_ip} was completed and the attack was successfully contained.
</p>
<p>
This alert was sent because you've opted to receive auto-mitigation alerts. You can disable this notification at any time
in your client area at <a href="{\$whmcs_url}">{\$whmcs_url}</a>. 
</p>
EOF,
            'created_at'    => date('Y-m-d H:i:s'),
        ) );
    }

    return array(
        'status' => 'success',
        'description' => 'OVH IP Manager successfully activated',
    );
}

function ovh_ip_manager_deactivate( ){
    full_query("DROP TABLE IF EXISTS mod_ovh_ip_manager_mitigation_alerts");
    full_query("DROP TABLE IF EXISTS mod_ovh_ip_manager_game_ddos_status");
    full_query("DROP TABLE IF EXISTS mod_ovh_ip_manager_customer_options");

    Capsule::table( 'tblemailtemplates' )->where( 'name', 'OVH auto mitigation enabled' )->delete();
    Capsule::table( 'tblemailtemplates' )->where( 'name', 'OVH auto mitigation disabled' )->delete();

    return array(
        'status' => 'success',
        'description' => 'OVH IP Manager successfully de-activated and will not be available in client area.',
    );
}
