<?php

// change the following paths if necessary
$yii = dirname(__FILE__) . '/framework/yii.php';
$config = dirname(__FILE__) . '/protected/config/main.php';
require_once 'config.inc';
// remove the following line when in production mode
defined('YII_DEBUG') or define('YII_DEBUG', true);

require_once($yii);
Yii::createWebApplication($config);
session_start();
$modDB = Post::model();
$oAuth = new MicrosoftLogin;
//print_r($_GET);
//exit;
if (!empty($_GET['error'])) {
    $error_description = !empty($_GET['error_description']) ? $_GET['error_description'] : " Default error";
    echo $oAuth->errorMessage($error_description);
    exit;
}
//retrieve session data from database
$sessionData = $modDB->QuerySingle('SELECT * FROM tblAuthSessions WHERE txtSessionKey=\'' . $_SESSION['sessionkey'] . '\'');

if ($sessionData) {
    // Request token from Azure AD
    $oauthRequest = $oAuth->generateRequest('grant_type=authorization_code&client_id=' . _OAUTH_CLIENTID . '&redirect_uri=' . urlencode(_URL . '/oauth.php') . '&code=' . $_GET['code'] . '&code_verifier=' . $sessionData['txtCodeVerifier']);

    $response = $oAuth->postRequest('token', $oauthRequest);

    // Decode response from Azure AD. Extract JWT data from supplied access_token and id_token and update database.
    if (!$response) {
        echo $oAuth->errorMessage('Unknown error acquiring token');
        exit;
    }
    file_put_contents('test.txt', $response);
    $reply = json_decode($response);
    if (!empty($reply->error)) {
        echo $oAuth->errorMessage($reply->error_description);
        exit;
    }

    $idToken = base64_decode(explode('.', $reply->id_token)[1]);
    $modDB->updateData('tblAuthSessions', array('txtToken' => $reply->access_token, 'txtRefreshToken' => $reply->refresh_token, 'txtIDToken' => $idToken, 'txtRedir' => '', 'dtExpires' => date('Y-m-d H:i:s', strtotime('+' . $reply->expires_in . ' seconds'))), array('intAuthID' => $sessionData['intAuthID']));
    // Redirect user back to where they came from.
    // header('Location: ' . $sessionData['txtRedir']);
    header('Location: ' . _URL . '/index.php/site/login');
} else {
    header('Location: ' . _URL . '/index.php/site/login');
}
