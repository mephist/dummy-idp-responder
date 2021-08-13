<?php

// openssl req -new -x509 -days 365 -nodes -sha256 -out cfg/cert.pem -keyout cfg/key.pem

require('vendor/autoload.php');
require("src/IdentityProvider.php");
require("src/IdentityProviderResponder.php");

$saml_request = $_REQUEST['SAMLRequest'];
$relay_state = $_REQUEST['RelayState'];

define('BRAND_DOMAIN', 'kgdlm.brnd10255a33-a5ac1e.aqa.int.zone');
define('BRAND_ID', 41);


$config = [
    'idp' => [
        'id' => 'https://www.idp.com',
        'key' => __DIR__ . '/cfg/key.pem',
        'cert' => __DIR__ .'/cfg/cert.pem',
    ],
    'sps' => [
        "https://".BRAND_DOMAIN."/auth/realms/sr".BRAND_ID => "https://".BRAND_DOMAIN."/auth/realms/sr".BRAND_ID."/broker/saml/endpoint",
    ]

];

$idp = new IdentityProvider($config);
$responder = new IdentityProviderResponder($idp);

// Hardcoded. Change to somethng like `$user_data = ['email' => $_SESSION['cbcLogin']];`

$user_data = [
	'email' => 'saml@tester.com'
];

$saml_response = $responder->createSamlResponse($saml_request, $user_data);


echo $responder->preparePostBinding($saml_response, $relay_state)->getContent();

