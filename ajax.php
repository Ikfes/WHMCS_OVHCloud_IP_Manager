<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, HEAD, OPTIONS');

use WHMCS\Database\Capsule;
use \Ovh\Api;

define( "CLIENTAREA", true );

require( "../../../init.php" );
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/common.php';

//session_start();

$ca = new WHMCS_ClientArea();
if ( ! $ca->isLoggedIn() ) {
    _ovh_ip_manager_send_json( array( 'error' => 'Operation not permitted.' ) );
}

if ( empty( $_REQUEST['action'] ) ) {
    _ovh_ip_manager_send_json( array( 'error' => 'Unspecified operation.' ) );
}

// add request handlers
_ovh_ip_manager_handle_requests( );

/**
 * Send data as json and exit.
 *
 * @param mixed $data
 */
function _ovh_ip_manager_send_json( $data ){
    if ( ! headers_sent() ) {
        header( 'Content-Type: application/json' );
    }
    die(json_encode($data));
}

/**
 * Check if an IP is under permanent mitigation.
 *
 * @param string $ip
 * @param string|null $ipBlock
 * @return bool|void
 *
 */
function _ovh_ip_manager_on_permanent_mitigation( $ip, $ipBlock = null ) {
    $ips = array( );
    if ( ! $ipBlock ) {
        $ipBlock = _ovh_ip_manager_get_ip_block($ip);
        if ( ! $ipBlock ) {
            return;
        }
    }
    $config = _ovh_ip_manager_get_option( );
    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        return;
    }
    try {
        $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/mitigation/$ip");
    } catch (GuzzleHttp\Exception\ClientException $e) {
        return false;
    }

    if ( ! isset( $result['permanent'] ) ) {
        return false;
    }

    if ( ! empty( $result['state'] ) && 'removalPending' === $result['state'] ) {
        return ! $result['permanent'];
    }

    return $result['permanent'];
}

/**
 * Check if an IP is has firewall enabled.
 *
 * @param string $ip
 * @param string|null $ipBlock
 * @return bool|null
 *
 */
function _ovh_ip_manager_network_firewall_enabled( $ip, $ipBlock = null ) {
    $ips = array( );
    if ( ! $ipBlock ) {
        $ipBlock = _ovh_ip_manager_get_ip_block($ip);
        if ( ! $ipBlock ) {
            return false;
        }
    }
    $config = _ovh_ip_manager_get_option( );
    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        return false;
    }
    try {
        $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/firewall/$ip");
    } catch (GuzzleHttp\Exception\ClientException $e) {
        return false;
    }
    if ( ! isset( $result['enabled'] ) OR empty( $result['state'] ) ) {
        return false;
    }
    if ( 'enableFirewallPending' === $result['state'] ) {
        return true;
    }
    elseif ( 'disableFirewallPending' === $result['state'] ) {
        return false;
    }
    return $result['enabled'];
}

/**
 * Check if an IP is has game firewall enabled.
 *
 * @param string $ip
 * @param string|null $ipBlock
 * @return bool|null
 *
 */
function _ovh_ip_manager_game_firewall_enabled( $ip, $ipBlock = null ) {
    $ips = array( );
    if ( ! $ipBlock ) {
        $ipBlock = _ovh_ip_manager_get_ip_block($ip);
        if ( ! $ipBlock ) {
            return false;
        }
    }
    $config = _ovh_ip_manager_get_option( );
    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        return false;
    }
    try {
        $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/game/$ip");
    } catch (GuzzleHttp\Exception\ClientException $e) {
        return false;
    }
    if ( ! isset( $result['firewallModeEnabled'] ) OR empty( $result['state'] ) ) {
        return false;
    }
    if ( 'firewallModeEnablePending' === $result['state'] ) {
        return true;
    }
    elseif ( 'firewallModeDisablePending' === $result['state'] ) {
        return false;
    }
    return $result['firewallModeEnabled'];
}

/**
 * Dispatch requests to matched handlers
 */
function _ovh_ip_manager_handle_requests( ){
    if ( function_exists( '_ovh_ip_manager_request_' . $_REQUEST['action'] ) ) {
        call_user_func( '_ovh_ip_manager_request_' . $_REQUEST['action'] );
    }
    else {
        _ovh_ip_manager_send_json( array( 'error' => sprintf( 'Unknown operation: %s.', $_REQUEST['action'] ) ) );
    }
}

/**
 * Sort firewall rules by sequence.
 *
 * @param array $rule1
 * @param array $rule2
 * @return int
 */
function _ovh_ip_manager_sort_network_firewall_rules( $rule1, $rule2 ) {
    if ( empty( $rule1['sequence'] ) OR empty( $rule2['sequence'] ) ) {
        return -1;
    }
    if ( $rule1['sequence'] === $rule2['sequence'] ) {
        return 0;
    }
    return $rule1['sequence'] < $rule2['sequence'] ? -1 : 1;
}

// Request handlers

function _ovh_ip_manager_request_get_ips( ){
    $response = array();

    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }

    $ip = _ovh_ip_manager_get_service_ip( );

    if ( $ip ) {
        $ipBlock = _ovh_ip_manager_get_ip_block( $ip );
        if ( ! $ipBlock ) {
            _ovh_ip_manager_send_json( array( 'error' => 'Unable to find IP block' ) );
        }

        $alert = Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
            ->where( 'customer_id', $_SESSION['uid'] )
            ->where( 'ip_address', $ip )
            ->first();

        $response[] = array(
            'ip' => $ip,
            'reverse_dns' => gethostbyaddr( $ip ),
            'mitigation' => _ovh_ip_manager_on_permanent_mitigation($ip, $ipBlock) ? true : false,
            'notif_email' => $alert ? $alert->notif_email == 1 : false,
            'notif_discord' => $alert ? $alert->notif_discord == 1 : false,
            'game_ddos_available' => _ovh_ip_manager_game_ddos_available($ip, $ipBlock),
        );
    }

    _ovh_ip_manager_send_json( array( 'ips' => $response, ) );
}

function _ovh_ip_manager_request_change_mitigation( ){
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( ! isset( $_REQUEST['enable'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Mitigation status not specified.' ) );
    }
    $enable = 'yes' === $_REQUEST['enable'];

    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];

    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }

    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // get IPs on mitigation
    $ips_on_mitigation = array( );
    try {
        $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/mitigation");
    } catch (GuzzleHttp\Exception\ClientException $e) {

    }
    if ( is_array( $result ) && ! isset( $result['message'] ) ) {
        $ips_on_mitigation = $result;
    }

    // Enable permanent mitigation
    if ( $enable ) {
        // make sure mitigation exists
        if ( ! in_array( $server_ip, $ips_on_mitigation ) ) {
            try {
                $result = $conn->post("/ip/" . rawurlencode($ipBlock) . "/mitigation", array( 'ipOnMitigation' => $server_ip ));
                if ( ! empty( $result['message'] ) ) {
                    _ovh_ip_manager_send_json( array( 'error' => 'Unable to set IP on mitigation.' ) );
                }
            } catch (GuzzleHttp\Exception\ClientException $e) {
                _ovh_ip_manager_send_json( array( 'error' => 'Unable to set IP on mitigation.' ) );
            }
        }
        // make sure permanent is set
        try {
            $result = $conn->put("/ip/" . rawurlencode($ipBlock) . "/mitigation/" . $server_ip, array( 'permanent' => $enable ));
            _ovh_ip_manager_send_json( array( 'done' => true, 'enabled' => _ovh_ip_manager_on_permanent_mitigation( $ip, $ipBlock ) ) );
        } catch (GuzzleHttp\Exception\ClientException $e) {
            _ovh_ip_manager_send_json( array( 'done' => false, 'enabled' => _ovh_ip_manager_on_permanent_mitigation( $ip, $ipBlock ) ) );
        }
    }
    // disable permanent mitigation
    else {
        try {
            $result = $conn->delete("/ip/" . rawurlencode($ipBlock) . "/mitigation/" . $server_ip);
            _ovh_ip_manager_send_json( array( 'done' => true, 'enabled' => _ovh_ip_manager_on_permanent_mitigation( $ip, $ipBlock ), 'result' => $result ) );
        } catch (GuzzleHttp\Exception\ClientException $e) {
            _ovh_ip_manager_send_json( array( 'done' => false, 'enabled' => _ovh_ip_manager_on_permanent_mitigation( $ip, $ipBlock ), 'error' => _ovh_ip_manager_format_error( $e->getMessage() ) ) );
        }
    }

}

function _ovh_ip_manager_request_get_network_firewall_rules( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // get firewall status
    $firewall_enabled = _ovh_ip_manager_network_firewall_enabled($ip, $ipBlock);

    // get firewall rules
    $rules = array( );
    $sequences = array( );
    try {
        $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/firewall/$ip/rule");
        if ( is_array( $result ) ) {
            $sequences = $result;
        }
    } catch (GuzzleHttp\Exception\ClientException $e) {

    }

    foreach ( $sequences as $sequence ) {
        try {
            $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/firewall/$ip/rule/$sequence");
            if ( ! empty( $result['sequence'] ) ) {
                $rules[] = $result;
            }
        } catch (GuzzleHttp\Exception\ClientException $e) {

        }
    }

    usort( $rules, '_ovh_ip_manager_sort_network_firewall_rules' );

    _ovh_ip_manager_send_json( array( 'rules' => $rules, 'firewall_enabled' => $firewall_enabled, ) );
}

function _ovh_ip_manager_request_add_network_firewall_rule( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // add new firewall rule
    $rules = array( );
    try {
        $options = array(
            'action' => $_REQUEST['operation'],
            'protocol' => $_REQUEST['protocol'],
            'sequence' => $_REQUEST['sequence'],
        );
        if ( $_REQUEST['destinationPort'] ) {
            $options['destinationPort'] = $_REQUEST['destinationPort'];
        }
        if ( $_REQUEST['source'] ) {
            $options['source'] = $_REQUEST['source'];
        }
        if ( $_REQUEST['sourcePort'] ) {
            $options['sourcePort'] = $_REQUEST['sourcePort'];
        }
        if ( ! empty( $_REQUEST['protocol'] ) && 'TCP' === strtoupper( $_REQUEST['protocol'] ) ) {
            $tcp_options = array();
            if ( ! empty( $_REQUEST['fragments'] ) && $_REQUEST['fragments'] === 'yes' ) {
                $tcp_options['fragments'] = true;
            }
            if ( ! empty( $_REQUEST['flags'] ) && $_REQUEST['flags'] !== 'none' ) {
                $tcp_options['option'] = $_REQUEST['flags'];
            }
            if ( ! empty( $tcp_options ) ) {
                $options['tcpOption'] = $tcp_options;
            }
        }
        $result = $conn->post("/ip/" . rawurlencode($ipBlock) . "/firewall/$ip/rule", $options);
        // print_r($result);

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ) ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_delete_network_firewall_rule( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( ! isset( $_REQUEST['sequence'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified rule sequence.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // get firewall rules
    $rules = array( );
    try {
        $result = $conn->delete("/ip/" . rawurlencode($ipBlock) . "/firewall/$ip/rule/" . $_REQUEST['sequence']);
        // print_r($result);

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ), 'raw' => $error ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_enable_network_firewall( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( ! isset( $_REQUEST['enable'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified status.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // update firewall status
    $rules = array( );
    try {
        $result = $conn->put("/ip/" . rawurlencode($ipBlock) . "/firewall/$ip/", array( 'enabled' => $_REQUEST['enable'] === 'yes' ));
        print_r($result);

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ) ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_get_game_firewall_rules( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // get firewall status
    $firewall_enabled = _ovh_ip_manager_game_firewall_enabled($ip, $ipBlock);

    // get firewall rules
    $rules = array( );
    $ids = array( );
    try {
        $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/game/$ip/rule");
        if ( is_array( $result ) ) {
            $ids = $result;
        }
    } catch (GuzzleHttp\Exception\ClientException $e) {
        echo $e->getMessage();
    }

    foreach ( $ids as $id ) {
        try {
            $result = $conn->get("/ip/" . rawurlencode($ipBlock) . "/game/$ip/rule/$id");
            if ( ! empty( $result['ports'] ) ) {
                $result['id'] = $id;
                $rules[] = $result;
            }
        } catch (GuzzleHttp\Exception\ClientException $e) {

        }
    }

    _ovh_ip_manager_send_json( array( 'rules' => $rules, 'firewall_enabled' => $firewall_enabled, ) );
}

function _ovh_ip_manager_request_add_game_firewall_rule( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( empty( $_REQUEST['protocol'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified protocol.' ) );
    }
    if ( empty( $_REQUEST['fromPort'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified source port.' ) );
    }
    if ( empty( $_REQUEST['toPort'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified destination port.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // add game firewall rule
    $rules = array( );
    try {
        $result = $conn->post("/ip/" . rawurlencode($ipBlock) . "/game/$ip/rule", array(
            'protocol' => $_REQUEST['protocol'],
            'ports' => array(
                'from' => $_REQUEST['fromPort'],
                'to' => $_REQUEST['toPort'],
            )
        ));
        // print_r($result);

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ) ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_delete_game_firewall_rule( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( ! isset( $_REQUEST['id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified rule ID.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // get firewall rules
    $rules = array( );
    try {
        $result = $conn->delete("/ip/" . rawurlencode($ipBlock) . "/game/$ip/rule/" . $_REQUEST['id']);
        // print_r($result);

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ) ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_enable_game_firewall( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( ! isset( $_REQUEST['enable'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified status.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // update firewall status
    $rules = array( );
    try {
        $result = $conn->put("/ip/" . rawurlencode($ipBlock) . "/game/$ip/", array( 'firewallModeEnabled' => $_REQUEST['enable'] === 'yes' ));
        // print_r($result);

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ) ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_save_reverse_dns( ) {
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( empty( $_REQUEST['domain'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified domain.' ) );
    }
    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];
    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }
    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $config = _ovh_ip_manager_get_option( );

    try {
        $conn = new Api( $config['app_key'], $config['secret_key'], 'ovh-eu', $config['consumer_key'] );
    } catch (\Ovh\Exceptions\InvalidParameterException $e) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to configure API client.' ) );
    }

    // update firewall status
    $rules = array( );
    try {
        $result = $conn->post("/ip/" . rawurlencode($ipBlock) . "/reverse", array(
            'ipReverse' => $ip,
            'reverse' => $_REQUEST['domain']
        ));
        // print_r($result);
        // die('ok');

    } catch (GuzzleHttp\Exception\ClientException $e) {
        $response = $e->getResponse();
        $result = $response->getBody()->getContents();
        $error = json_decode($result, true);
        if ( ! empty( $error['message'] ) ) {
            $result = $error['message'];
        }
        _ovh_ip_manager_send_json( array( 'error' => _ovh_ip_manager_format_error( $result ) ) );
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_change_mitigation_alert( ){
    if ( empty( $_REQUEST['service_id'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified service.' ) );
    }
    if ( ! isset( $_REQUEST['enable'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Alert status not specified.' ) );
    }
    $enable = 'yes' === $_REQUEST['enable'];

    if ( empty( $_REQUEST['ip'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified IP address.' ) );
    }
    $server_ip = $_REQUEST['ip'];

    if ( empty( $_REQUEST['notif_type'] ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unspecified notification type.' ) );
    }
    if ( ! in_array( $_REQUEST['notif_type'], array( 'email', 'discord' ) ) ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Allowed notification types: email and discord.' ) );
    }

    $ipBlock = _ovh_ip_manager_get_ip_block($server_ip);
    if ( ! $ipBlock ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Unable to find block for this IP address.' ) );
    }

    $ip = _ovh_ip_manager_get_service_ip( );
    if ( $server_ip !== $ip ) {
        _ovh_ip_manager_send_json( array( 'error' => 'Restricted operation on this IP address.' ) );
    }

    $alert = Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )->where( 'customer_id', $_SESSION['uid'] )->where( 'ip_address', $server_ip )->first();
    if ( ! $alert ) {
        Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )->insert( array(
            'customer_id'   => $_SESSION['uid'],
            'ip_address'    => $server_ip,
            'ip_block'      => $ipBlock,
            'service_id'    => $_REQUEST['service_id'],
            'created_at'    => date('Y-m-d H:i:s'),
        ) );
    }

    Capsule::table( 'mod_ovh_ip_manager_mitigation_alerts' )
        ->where( 'customer_id', $_SESSION['uid'] )
        ->where( 'ip_address', $server_ip )
        ->update(array(
            'notif_' . $_REQUEST['notif_type'] => ( $enable ? '1' : '0' )
        ));

    _ovh_ip_manager_send_json( array( 'done' => true ) );

}

function _ovh_ip_manager_request_save_discord_webhook_url( ){
    $url = ! empty( $_REQUEST['url'] ) ? trim( $_REQUEST['url'] ) : '';
    $option = Capsule::table( 'mod_ovh_ip_manager_customer_options' )->where( 'customer_id', $_SESSION['uid'] )->where( 'option_name', 'discord_webhook_url' )->first();
    if ( ! $option ) {
        Capsule::table( 'mod_ovh_ip_manager_customer_options' )->insert( array(
            'customer_id'   => $_SESSION['uid'],
            'option_name'   => 'discord_webhook_url',
            'option_value'  => $url,
            'created_at'    => date('Y-m-d H:i:s'),
        ) );
    }
    else {
        Capsule::table( 'mod_ovh_ip_manager_customer_options' )
            ->where( 'customer_id', $_SESSION['uid'] )
            ->where( 'option_name', 'discord_webhook_url' )
            ->update(array(
                'option_value' => $url,
                'updated_at' => date('Y-m-d H:i:s'),
            ));
    }

    _ovh_ip_manager_send_json( array( 'done' => true ) );
}

function _ovh_ip_manager_request_get_discord_webhook_url( ){
    $url = '';
    $option = Capsule::table( 'mod_ovh_ip_manager_customer_options' )->where( 'customer_id', $_SESSION['uid'] )->where( 'option_name', 'discord_webhook_url' )->first();
    if ( $option ) {
        $url = $option->option_value;
    }
    _ovh_ip_manager_send_json( array( 'url' => $url ) );
}

function _ovh_ip_manager_format_error( $error ) {
    if ( is_string( $error ) && strpos( $error, "needs to be ok in order to" ) !== false ) {
        $error = "Your last request is still pending. Please wait a few seconds and try again!";
    }
    return $error;
}
