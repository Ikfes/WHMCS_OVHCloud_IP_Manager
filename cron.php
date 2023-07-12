<?php
use WHMCS\Database\Capsule;

require( "../../../init.php" );
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/common.php';

_ovh_ip_manager_output( 'CRON STARTED', true, true, 'default' );
_ovh_ip_manager_log( __DIR__ . '/cron.log', 'CRON STARTED' );

if ( ! _ovh_ip_manager_is_enabled() ) {
    _ovh_ip_manager_output( 'cron is disabled', true, true, 'warning' );
    _ovh_ip_manager_log( __DIR__ . '/cron.log', 'cron is disabled' );
    exit();
}

// are mitigation-ON IPs back to normal ?
_ovh_ip_manager_output( 'checking status change for IP on auto-mitigation...', true, true, 'info' );
_ovh_ip_manager_log( __DIR__ . '/cron.log', 'checking status change for IP on auto-mitigation...' );

$alerts = _ovh_ip_manager_get_detected_auto_mitigation_alerts();
if ( count( $alerts ) === 0 ) {
    _ovh_ip_manager_output( 'no IP on auto-mitigation' );
    _ovh_ip_manager_log( __DIR__ . '/cron.log', 'no IP on auto-mitigation' );
}
else {
    _ovh_ip_manager_output( sprintf( 'processing %s alert%s', count( $alerts ), ( count( $alerts ) > 1 ? 's' : '' ) ) );
    _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( 'processing %s alert%s', count( $alerts ), ( count( $alerts ) > 1 ? 's' : '' ) ) );

    foreach ( $alerts as $alert ) {
        // print_r($alert);

        _ovh_ip_manager_output( sprintf( '%s: processing (service #%s)...', $alert->ip_address, $alert->service_id ) );
        _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: processing (service #%s)...', $alert->ip_address, $alert->service_id ) );

        $mitigation_removed = false;
        try {
            $result = _ovh_ip_manager_get_mitigation_status( $alert->ip_address, $alert->ip_block );
        }
        catch (\Exception $ex) {
            if ( preg_match( '/does not exist/is', $ex->getMessage() ) ) {
                $mitigation_removed = true;
                _ovh_ip_manager_output( sprintf( '%s: auto-mitigation removed', $alert->ip_address ), true, true, 'warning' );
                _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation removed', $alert->ip_address ) );
            }
            else {
                _ovh_ip_manager_output( sprintf( '%s: failed retrieving mitigation status; error: %s', $alert->ip_address, $ex->getMessage() ), true, true, 'error' );
                _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: failed retrieving mitigation status; error: %s', $alert->ip_address, $ex->getMessage() ) );

                continue;
            }
        }

        if ( ! $mitigation_removed && ( ! is_array( $result ) OR ! array_key_exists( 'auto', $result ) ) ) {
            _ovh_ip_manager_output( sprintf( '%s: auto-mitigation status not available', $alert->ip_address ), true, true, 'error' );
            _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation status not available', $alert->ip_address ) );
            continue;
        }

        if ( ! $mitigation_removed && $result['auto'] ) {
            _ovh_ip_manager_output( sprintf( '%s: no change detected in auto-mitigation status (still enabled)', $alert->ip_address ) );
            _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: no change detected in auto-mitigation status (still enabled)', $alert->ip_address ) );
            continue;
        }

        Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
            ->where( 'id', $alert->id )
            ->update(array(
                'mitigation_at' => '0000-00-00 00:00:00',
                'updated_at' => date('Y-m-d H:i:s'),
            ));

        if ($alert->notif_email) {
          _ovh_ip_manager_output( sprintf( '%s: auto-mitigation disabled; change just detected, sending email alert...', $alert->ip_address ) );
          _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation disabled; change just detected, sending email alert...', $alert->ip_address ) );

          $sent = localAPI('SendEmail', array(
              'id'            => $alert->service_id,
              'messagename'   => 'OVH auto mitigation disabled',
          ));
          _ovh_ip_manager_output( $sent );
          _ovh_ip_manager_log( __DIR__ . '/cron.log', $sent );

          if ( isset( $sent['result'] ) && $sent['result'] == 'success' ) {
              Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
                  ->where( 'id', $alert->id )
                  ->update(array(
                      'alert_sent_at' => date('Y-m-d H:i:s'),
                  ));

              _ovh_ip_manager_output( sprintf( '%s: alert successfully sent via email', $alert->ip_address ), true, true, 'success' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: alert successfully sent via email', $alert->ip_address ) );
          }
          else {
              _ovh_ip_manager_output( sprintf( '%s: failed sending alert via email', $alert->ip_address ), true, true, 'error' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: failed sending alert via email', $alert->ip_address ) );
          }
        }

        if ($alert->notif_discord) {
          _ovh_ip_manager_output( sprintf( '%s: auto-mitigation disabled; change just detected, sending discord alert...', $alert->ip_address ) );
          _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation disabled; change just detected, sending discord alert...', $alert->ip_address ) );
          $sent = _ovh_ip_manager_send_discord_message($alert->customer_id,
            sprintf( 'This message is to confirm that the auto-mitigation procedure on your server %s was completed and the attack was successfully contained.', $alert->ip_address)
          );

          if ( $sent ) {
              Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
                  ->where( 'id', $alert->id )
                  ->update(array(
                      'alert_sent_at' => date('Y-m-d H:i:s'),
                  ));

              _ovh_ip_manager_output( sprintf( '%s: alert successfully sent to discord', $alert->ip_address ), true, true, 'success' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: alert successfully sent to discord', $alert->ip_address ) );
          }
          else {
              _ovh_ip_manager_output( sprintf( '%s: failed sending alert to discord', $alert->ip_address ), true, true, 'error' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: failed sending alert to discord', $alert->ip_address ) );
          }
        }
    }
}

// are mitigation-OFF IPs on mitigation ?
_ovh_ip_manager_output( 'checking status change for IP with auto-mitigation disabled...', true, true, 'info' );
_ovh_ip_manager_log( __DIR__ . '/cron.log', 'checking status change for IP with auto-mitigation disabled...' );

$alerts = _ovh_ip_manager_get_detected_auto_mitigation_alerts( false );
if ( count( $alerts ) === 0 ) {
    _ovh_ip_manager_output( 'no IP on auto-mitigation' );
    _ovh_ip_manager_log( __DIR__ . '/cron.log', 'no IP on auto-mitigation' );
}
else {
    _ovh_ip_manager_output( sprintf( 'processing %s alert%s', count( $alerts ), ( count( $alerts ) > 1 ? 's' : '' ) ) );
    _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( 'processing %s alert%s', count( $alerts ), ( count( $alerts ) > 1 ? 's' : '' ) ) );

    foreach ( $alerts as $alert ) {
        // print_r($alert);

        _ovh_ip_manager_output( sprintf( '%s: processing (service #%s)...', $alert->ip_address, $alert->service_id ) );
        _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: processing (service #%s)...', $alert->ip_address, $alert->service_id ) );

        $mitigation_removed = false;
        try {
            $result = _ovh_ip_manager_get_mitigation_status( $alert->ip_address, $alert->ip_block );
        }
        catch (\Exception $ex) {
            if ( preg_match( '/does not exist/is', $ex->getMessage() ) ) {
                $mitigation_removed = true;
                _ovh_ip_manager_output( sprintf( '%s: auto-mitigation settings not found', $alert->ip_address ), true, true, 'warning' );
                _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation settings not found', $alert->ip_address ) );
            }
            else {
                _ovh_ip_manager_output( sprintf( '%s: failed retrieving mitigation status; error: %s', $alert->ip_address, $ex->getMessage() ), true, true, 'error' );
                _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: failed retrieving mitigation status; error: %s', $alert->ip_address, $ex->getMessage() ) );
            }
            continue;
        }

        if ( ! is_array( $result ) OR ! array_key_exists( 'auto', $result ) ) {
            _ovh_ip_manager_output( sprintf( '%s: auto-mitigation status not available', $alert->ip_address ), true, true, 'error' );
            _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation status not available', $alert->ip_address ) );
            continue;
        }

        if ( ! $result['auto'] ) {
            _ovh_ip_manager_output( sprintf( '%s: no change detected in auto-mitigation status (disabled)', $alert->ip_address ) );
            _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: no change detected in auto-mitigation status (disabled)', $alert->ip_address ) );
            continue;
        }

        Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
            ->where( 'id', $alert->id )
            ->update(array(
                'mitigation_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ));

        if ($alert->notif_email) {
          _ovh_ip_manager_output( sprintf( '%s: auto-mitigation enabled; change just detected, sending email alert...', $alert->ip_address ) );
          _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation enabled; change just detected, sending email alert...', $alert->ip_address ) );

          $sent = localAPI('SendEmail', array(
              'id'            => $alert->service_id,
              'messagename'   => 'OVH auto mitigation enabled',
          ));

          _ovh_ip_manager_output( $sent );
          _ovh_ip_manager_log( __DIR__ . '/cron.log', $sent );

          if ( isset( $sent['result'] ) && $sent['result'] == 'success' ) {
              Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
                  ->where( 'id', $alert->id )
                  ->update(array(
                      'alert_sent_at' => date('Y-m-d H:i:s'),
                  ));

              _ovh_ip_manager_output( sprintf( '%s: alert successfully sent via email', $alert->ip_address ), true, true, 'success' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: alert successfully sent via email', $alert->ip_address ) );
          }
          else {
              _ovh_ip_manager_output( sprintf( '%s: failed sending alert via email', $alert->ip_address ), true, true, 'error' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: failed sending alert via email', $alert->ip_address ) );
          }
        }

        if ($alert->notif_discord) {
          _ovh_ip_manager_output( sprintf( '%s: auto-mitigation enabled; change just detected, sending discord alert...', $alert->ip_address ) );
          _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: auto-mitigation enabled; change just detected, sending discord alert...', $alert->ip_address ) );
          $sent = _ovh_ip_manager_send_discord_message($alert->customer_id,
            sprintf( 'This message is to confirm that your server %s is under mitigation procedure to contain a possible attack we have automatically detected. You\'ll receive another alert when this procedure is lifted.', $alert->ip_address)
          );

          if ( $sent ) {
              Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
                  ->where( 'id', $alert->id )
                  ->update(array(
                      'alert_sent_at' => date('Y-m-d H:i:s'),
                  ));

              _ovh_ip_manager_output( sprintf( '%s: alert successfully sent to discord', $alert->ip_address ), true, true, 'success' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: alert successfully sent to discord', $alert->ip_address ) );
          }
          else {
              _ovh_ip_manager_output( sprintf( '%s: failed sending alert to discord', $alert->ip_address ), true, true, 'error' );
              _ovh_ip_manager_log( __DIR__ . '/cron.log', sprintf( '%s: failed sending alert to discord', $alert->ip_address ) );
          }
        }
    }
}