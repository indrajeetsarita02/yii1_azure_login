<?php
/* config.inc Configuration for oAuth Demo project
 *
 * Katy Nicholson, last updated 17/11/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 

***RENAME TO config.inc ***

*/
// MySQL connection details
define('_MYSQL_HOST', 'localhost');
define('_MYSQL_USER', 'root');
define('_MYSQL_DB', 'test');
define('_MYSQL_PASS', '');


// oAuth details



// TENANTID: Your tenant's ID if you set up the app reg as single tenant, otherwise 'common'

//Scope needs to include the services you wish to access - at a minimum you'll need openid and offline_access for logging on to work. Add in user.read if you want to query user profile via Graph. Separate with %20.

//define('_OAUTH_TENANTID', 'f8cdef31-a31e-4b4a-93e4-5f571e91255a');
define('_OAUTH_TENANTID', 'common'); // consumers or /common
define('_OAUTH_CLIENTID', '4c11e782-d521-456b-aab2-440e7041d787');
define('_OAUTH_LOGOUT', 'https://login.microsoftonline.com/common/wsfederation?wa=wsignout1.0');
//define('_OAUTH_SCOPE', 'User.Read');
define('_OAUTH_SCOPE', 'openid%20offline_access%20profile%20user.read');

// Define either the client secret, or the client certificate details
// method = 'certificate' or 'secret'

define('_OAUTH_METHOD', 'secret');

define('_OAUTH_SECRET', '~ty8Q~n6wds3t_N1.x4~O_SBk2jv84878fj-1diV');
define('_OAUTH_AUTH_CERTFILE', '/path/to/certificate.crt');
define('_OAUTH_AUTH_KEYFILE', '/path/to/privatekey.pem');

// on Windows, the certificate paths should be in the form c:/path/to/cert.crt


// URL to this website, no trailing slash.
define('_URL', 'https://localhost/yiidemo');
?>

