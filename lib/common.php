<?php
use WHMCS\Database\Capsule;
use \Ovh\Api;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Get module admin settings.
 *
 * @return array
 */
function _ovh_ip_manager_get_option( ){
    $result = Capsule::table( 'tbladdonmodules' )->where( 'module', 'ovh_ip_manager' )->get();
    $items = array();
    if ( $result && is_array( $result ) ) {
        foreach ( $result as $item ) {
            $items[ $item->setting ] = $item->value;
        }
    }
    return $items;
}

/**
 * Get the dedicated IP associated to the current service
 *
 * @return string|null
 */
function _ovh_ip_manager_get_service_ip( $service_id = null ) {
    $ip = null;
    $options = array(
        'clientid' => $_SESSION['uid'],
        'serviceid' => ( $service_id ? $service_id : $_REQUEST['service_id'] ),
    );
    $result = localAPI( 'GetClientsProducts', $options );
    if ( isset( $result['products']['product'] ) && isset( $result['products']['product'][0]['dedicatedip'] ) ) {
        $ip = $result['products']['product'][0]['dedicatedip'];
    }
    return $ip;
}



/**
 * Check if given IP address belongs to IP range in CIDR format.
 *
 * @param string $ip
 * @param string $range
 * @return bool
 */
function _ovh_ip_manager_ip_in_range( $ip, $range ) {
    if ( strpos( $range, '/' ) == false ) {
        $range .= '/32';
    }
    // $range is in IP/CIDR format eg 127.0.0.1/24
    list( $range, $netmask ) = explode( '/', $range, 2 );
    $range_decimal = ip2long( $range );
    $ip_decimal = ip2long( $ip );
    $wildcard_decimal = pow( 2, ( 32 - $netmask ) ) - 1;
    $netmask_decimal = ~ $wildcard_decimal;
    return ( ( $ip_decimal & $netmask_decimal ) == ( $range_decimal & $netmask_decimal ) );
}

/**
 * Retrieve all IPs.
 *
 * @return array
 */
function _ovh_ip_manager_get_ips( ) {
    $ips = array( );
    $config = _ovh_ip_manager_get_option( );
    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        return $ips;
    }
    $result = $conn->get('/ip/');
    if ( is_array( $result ) && ! isset( $result['message'] ) ) {
        $ips = $result;
    }
    return $ips;
}

/**
 * Find the IP block associated to a given IP.
 *
 * @param string $ip
 * @return string|null
 */
function _ovh_ip_manager_get_ip_block( $ip ) {
    $ipBlock = null;

    try {
        $ips = _ovh_ip_manager_get_ips( );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        return $ipBlock;
    }

    foreach ( $ips as $block ) {
        if ( preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $block ) && _ovh_ip_manager_ip_in_range( $ip, $block ) ) {
            $ipBlock = $block;
            break;
        }
    }

    return $ipBlock;
}

/**
 * Get mitigation details for a given IP address.
 *
 * @return array
 */
function _ovh_ip_manager_get_mitigation_status( $ip, $block = null ) {
    $result = array( );
    if ( $block === null ) {
        $block = _ovh_ip_manager_get_ip_block( $ip );
        if ( ! $block ) {
            return $result;
        }
    }
    $config = _ovh_ip_manager_get_option( );
    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        return $result;
    }
    $response = $conn->get("/ip/" . rawurlencode($block) . "/mitigation/" . $ip);
    _ovh_ip_manager_output( $response );
    _ovh_ip_manager_log( __DIR__ . '/cron.log', $response );
    if ( is_array( $response ) && ! isset( $response['message'] ) ) {
        $result = $response;
    }
    return $result;
}

function _ovh_ip_manager_game_ddos_available( $ip, $block = null, $service_id = null ) {
    $result = false;

    $item = Capsule::table( 'mod_ovh_ip_manager_game_ddos_status' )->where( 'ip_address', $ip )->first();
    if ( $item ) {
        $result = ( 1 == $item->available );
    }
    else {
        if ( $block === null ) {
            $block = _ovh_ip_manager_get_ip_block( $ip );
            if ( ! $block ) {
                return $result;
            }
        }
        if ( $service_id === null && ! empty( $_REQUEST['service_id'] ) ) {
            $service_id = $_REQUEST['service_id'];
        }
        $config = _ovh_ip_manager_get_option( );
        try {
            $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
        } catch (\Ovh\Exceptions\InvalidParameterException $e) {
            return $result;
        }
        try {
            $response = $conn->get("/ip/" . rawurlencode($block) . "/game/" . $ip);
        } catch ( GuzzleHttp\Exception\ClientException $e ) {

        }
        $available = ( is_array( $response ) && ! empty( $response['ipOnGame'] ) );
        Capsule::table( 'mod_ovh_ip_manager_game_ddos_status' )->insert( array(
            'customer_id'   => $_SESSION['uid'],
            'ip_address'    => $ip,
            'ip_block'      => $block,
            'service_id'    => $service_id,
            'available'     => $available,
            'created_at'    => date('Y-m-d H:i:s'),
        ) );
        $result = $available;
    }

    return $result;
}

function _ovh_ip_manager_is_enabled( ) {
    $config = _ovh_ip_manager_get_option( );
    return ( ! empty( $config ) && is_array( $config ) && isset( $config['enabled'] ) );
}

function _ovh_ip_manager_get_detected_auto_mitigation_alerts( $detected = true ) {
    if ( $detected ) {
        $alerts = Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )->where( 'mitigation_at', '<>', '0000-00-00 00:00:00' )->get();
    } else {
        $alerts = Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )->where( 'mitigation_at', '0000-00-00 00:00:00' )->get();
    }
    if ( ! is_array( $alerts ) ) {
        $alerts = array();
    }
    return $alerts;
}

function _ovh_ip_manager_output( $message, $new_line = true, $date_prefix = true, $type = 'default' ) {
    if ( is_object( $message ) OR is_array( $message ) ) {
        $message = "\n" . print_r( $message, true );
    }

    $wrapper_start = '';
    $wrapper_end = '';
    if ( $type === 'error' ) {
        $wrapper_start = '<p style="color: red; font-weight: bold;">';
        $wrapper_end = '</p>';
    }
    elseif ( $type === 'success' ) {
        $wrapper_start = '<p style="color: green; font-weight: bold;">';
        $wrapper_end = '</p>';
    }
    elseif ( $type === 'info' ) {
        $wrapper_start = '<p style="color: dodgerblue; font-weight: bold;">';
        $wrapper_end = '</p>';
    }
    elseif ( $type === 'warning' ) {
        $wrapper_start = '<p style="color: darkorange; font-weight: bold;">';
        $wrapper_end = '</p>';
    }
    elseif ( $type === 'default' ) {
        $wrapper_start = '<p>';
        $wrapper_end = '</p>';
    }

    if ( $date_prefix ) {
        $message = sprintf( "[%s] %s", @date("c"), $message );
    }

    if ( $new_line ) {
        if ( "cli" === php_sapi_name() ) {
            echo "\n";
        }
        else {
            if ( $wrapper_start ) {
                echo $wrapper_start;
            }
            else {
                echo "<br />";
            }
        }
    }

    echo $message;

    if ( $wrapper_start && "cli" !== php_sapi_name( ) ) {
        echo $wrapper_end;
    }
}

function _ovh_ip_manager_log( $file, $message, $new_line = true, $date_prefix = true ) {
    if ( is_object( $message ) OR is_array( $message ) ) {
        $message = "\n" . print_r( $message, true );
    }
    if ( $date_prefix ) {
        $message = sprintf( "[%s] %s", @date("c"), $message );
    }
    if ( $new_line ) {
        $message = "\n" . $message;
    }
    file_put_contents( $file, $message, FILE_APPEND );
}

function _ovh_ip_manager_get_discord_webhook_url( $customer_id ) {
    $url = '';
    $option = Capsule::table( 'mod_ovh_ip_manager_customer_options' )->where( 'customer_id', $customer_id )->where( 'option_name', 'discord_webhook_url' )->first();
    if ( $option ) {
        $url = $option->option_value;
    }
    return $url;
}

function _ovh_ip_manager_send_discord_message( $customer_id, $message ) {
    $url = _ovh_ip_manager_get_discord_webhook_url( $customer_id );
    if ( ! $url ) {
        return 'Discord Webhook URL not configured';
    }
    if ( ! function_exists( 'curl_init' ) ) {
        return 'cURL library not available';
    }

    $client = new GuzzleHttp\Client();
    try {
      $client->post($url, ['json' => ['content' => $message]]);  
    } catch (Exception $e) {
      _ovh_ip_manager_output( $e->getMessage() );
      _ovh_ip_manager_log( __DIR__ . '/cron.log', $e->getMessage() );
      return false;
    }

    return true;
}