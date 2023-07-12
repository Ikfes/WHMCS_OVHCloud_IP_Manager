<?php
require( "../../../init.php" );
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/common.php';

use GuzzleHttp\Client;

// $r = _ovh_ip_manager_get_option();
// $r = _ovh_ip_manager_get_ips();
// $r = _ovh_ip_manager_get_mitigation_status( '66.70.162.209', '66.70.162.208/29' );

// echo '<pre>'.print_r($r, 1).'</pre>';
// exit;

// $options = array(
//     'id' => 62,
//     'messagename' => 'OVH auto mitigation disabled',
// );
// $results = localAPI('SendEmail', $options);
// print_r($results);




$url = _ovh_ip_manager_get_discord_webhook_url( 30 );
$client = new Client();
try {
  $client->post($url, ['json' => ['content' => 'straight from whmcs 22!']]);  
} catch (Exception $e) {
  echo $e->getMessage();
}