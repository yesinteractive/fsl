<?php
/* 
 * Helper functions written for FSL Micro Framework
 * Author: NRago
 *
 */

// Add strict typing declaration at the top
declare(strict_types=1);

// Add this at the beginning of the file after declare(strict_types=1);
function fsl_init_secure_session(): void {
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    
    session_start([
        'cookie_lifetime' => 0,
        'gc_maxlifetime' => 3600,
        'use_strict_mode' => true
    ]);
}

/* 
 *
 * fsl_encrypt
 *
 * encrypts a string and returns the encrypted string with appended 
 * initialization vector (iv) unique to encrypted string
 *
 * @string (string) String to be encrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */
function fsl_encrypt(string $string, ?string $key = null): string {
    $encryption_key = $key ?? option('global_encryption_key');
    
    // Validate encryption key
    if ($encryption_key === 'setyourkeyhere') {
        throw new RuntimeException(
            'Please set a secure encryption key in config/fsl_config.php. ' .
            'You can generate one by running: php -r "echo base64_encode(random_bytes(32));"'
        );
    }
    
    if (empty($encryption_key)) {
        throw new RuntimeException('Encryption key not set in config/fsl_config.php');
    }

    // Generate an initialization vector
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    
    // Encrypt using the original method for compatibility
    $encrypted = openssl_encrypt(
        $string,
        'aes-256-cbc',
        $encryption_key,
        0,
        $iv
    );
    
    if ($encrypted === false) {
        throw new RuntimeException('Encryption failed - please check your encryption key');
    }
    
    // Return in the original format with : separator
    return $encrypted . ':' . base64_encode($iv);
}

/*
 * fsl_decrypt
 *
 * decrypts a string encrypted with fsl_encrypt function
 * remember to include full string with appended IV and the ':' seperator
 *
 * @string (string) String to be decrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */
function fsl_decrypt(string $string, ?string $key = null): string {
    $encryption_key = $key ?? option('global_encryption_key');
    
    // Validate encryption key
    if ($encryption_key === 'setyourkeyhere') {
        throw new RuntimeException(
            'Please set a secure encryption key in config/fsl_config.php. ' .
            'You can generate one by running: php -r "echo base64_encode(random_bytes(32));"'
        );
    }
    
    if (empty($encryption_key)) {
        throw new RuntimeException('Encryption key not set in config/fsl_config.php');
    }
    
    // Split using the original : separator
    $parts = explode(':', $string);
    if (count($parts) !== 2) {
        throw new RuntimeException('Invalid encrypted data format');
    }
    
    $decrypted = openssl_decrypt(
        $parts[0],
        'aes-256-cbc',
        $encryption_key,
        0,
        base64_decode($parts[1])
    );
    
    if ($decrypted === false) {
        throw new RuntimeException(
            'Decryption failed - this usually means either:' . PHP_EOL .
            '1. The encryption key has changed since the data was encrypted' . PHP_EOL .
            '2. The encrypted data has been modified or corrupted'
        );
    }
    
    return $decrypted;
}

/*
 * fsl_scrub($string)
 *
 * removes xss threats from data. Use with all POST data references
 *
 * @string (string) String to be decrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */
function fsl_scrub(string $string): string {
        
        $xss = new xss_filter();
        $string = $xss->filter_it($string); 
        return $string;
}

/*
 * fsl_session_set
 *
 * sets a new session value with optional timeout in seconds
 * also used to set any cookie variable. all data is set encrypted with global key
 * @name (string) Name of session
 * @value (string) value of session
 * @timeoue (string) optional timeout of session
 * @return true
 */ 
function fsl_session_set(string $name, string $value, ?int $timeout = null): bool {
    // Regenerate session ID periodically for security
    if (!isset($_SESSION['last_regeneration']) || 
        time() - $_SESSION['last_regeneration'] > 300) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
    
    $_SESSION[$name] = fsl_encrypt($value);
    if ($timeout !== null) {
        $_SESSION[$name . '_timeout'] = time() + $timeout;
    }
    
    return true;
}

/*
 * fsl_session_check
 *
 * gets a session value and optionally resets a new value or timeout
 * if session doesn't exist or timed out, then returns false, else returns value of session
 * @name (string) Name of session
 * @value (string) value of session
 * @timeoue (string) optional timeout of session
 * @return true
 */ 
function fsl_session_check(string $name, ?string $value = null, ?int $timeout = null): mixed {
    if ((empty($_SESSION[$name]  )) || ( (!empty( $_SESSION[$name.'_timeout'])) &&  (time() >  $_SESSION[$name.'_timeout'])) )
    {  
      fsl_session_kill($name); //run kill session command
			return false;
    }
    else
    {
      if(!empty($value)) $_SESSION[$name]  = fsl_encrypt($value);
      if(!empty($timeout))  $_SESSION[$name.'_timeout'] = $timeout;
    }
    
      return fsl_decrypt($_SESSION[$name] );
}

/*
 * fsl_session_kill
 *
 * kills a session and associated timeout
 * @name (string) Name of session
 * returns true
 */ 

function fsl_session_kill(string $name): bool {
    // More thorough session cleanup
    unset($_SESSION[$name], $_SESSION[$name . '_timeout']);
    
    // Only destroy the whole session if explicitly requested
    if ($name === '*') {
        $_SESSION = array();
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }
        session_destroy();
    }
    
    return true;
}

/* 
 *
 * fsl_jwt_encode
 *
 * creates a JWT Token
 *
 * @array (array) Array to be encoded in JWT
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */
function fsl_jwt_encode($array,$key)
{
  return JWT::encode($array, $key);
}

/* 
 *
 * fsl_jwt_decode
 *
 * Decodes and validates a JWT Token and key combination
 *
 * @token (string) JWT to be decoded
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (array) or error if validations fails
 */
function fsl_jwt_decode($token,$key)
{
  return JWT::decode($token, $key);
}

/* 
 *
 * get_tiny_url
 *
 * Generates a Tiny URL 
 *
 * @url (string) url to be shortened
 * @return (string)  
 */
function fsl_get_tiny_url($url)  {  
	$ch = curl_init();  
	$timeout = 5;  
	curl_setopt($ch,CURLOPT_URL,'https://tinyurl.com/api-create.php?url='.$url);  
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);  
	curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,$timeout);  
	$data = curl_exec($ch);  
	curl_close($ch);
  
	return preg_replace("/^http:/i", "https:", $data);  
}
 

/*
 * fsl_gauth_check
 *
 * checks if glogin session is set to 1 if not returns false
 *
 * @string (string) String to be decrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */

function fsl_gauth_check(): bool {
    if ($_SESSION['glogin'] == 1)
    {
      return true;
    }
    else
    {
      return false;
    }
}


/*
 * fsl_gauth_getauthurl
 *
 * generates the auth url to use on google login button
 *
 * @string (string) String to be decrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */
function fsl_gauth_getauthurl()
	{
	
	$gClient = new Google_Client();
  $gClient->setApplicationName('Login');
  $gClient->setClientId(option('clientId'));
  $gClient->setClientSecret(option('clientSecret'));
  $gClient->setRedirectUri(option('redirectURL'));  
	//	$gClient->setHd(option('hd')); 
  $google_oauthV2 = new Google_Oauth2Service($gClient);
  $authUrl = $gClient->createAuthUrl();
  return $authUrl;
}

/*
 * fsl_gauth_gettoken
 *
 * verify token from gauth is valid. If it is, returns array of google parameters
 *
 * @string (string) String to be decrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */
 function fsl_gauth_gettoken()
  {
	$gClient = new Google_Client();
  $gClient->setApplicationName('Login');
  $gClient->setClientId(option('clientId'));
  $gClient->setClientSecret(option('clientSecret'));
  $gClient->setRedirectUri(option('redirectURL'));  
	//		$gClient->setHd(option('hd'));
  $google_oauthV2 = new Google_Oauth2Service($gClient);
  
    //google auth first
  if(isset($_GET['code'])){
	$gClient->authenticate($_GET['code']);
	$_SESSION['token'] = $gClient->getAccessToken();
	
	header('Location: ' . filter_var($redirectURL, FILTER_SANITIZE_URL));
  }

  if (isset($_SESSION['token'])) {
	$gClient->setAccessToken($_SESSION['token']);
  }
  //Call Google API

  if ($gClient->getAccessToken()) {
	//Get user profile data from google
      $gpUserProfile = $google_oauthV2->userinfo->get();

      /*  $gpUserData = array(
            'oauth_provider'=> 'google',
            'oauth_uid'     => $gpUserProfile['id'],
            'first_name'    => $gpUserProfile['given_name'],
            'last_name'     => $gpUserProfile['family_name'],
            'email'         => $gpUserProfile['email'],
            'gender'        => $gpUserProfile['gender'],
            'locale'        => $gpUserProfile['locale'],
            'picture'       => $gpUserProfile['picture'],
            'link'          => $gpUserProfile['link']
        ); */
       // $userData = $user->checkUser($gpUserData);
      //$output = $gpUserProfile['given_name'];
      //$uemail = $gpUserProfile['email'];
      $_SESSION['glogin'] =  1;

      $uemail = substr(strrchr($uemail, "@"), 1);
      if ($uemail == "konghq.com"){
        header('Location: ' . option('base_uri') . 'home/');
      }else {
        header('Location: ' . option('base_uri') . 'logout/');
      }
      return $gpUserData;
    
  } else {
	 
	header('Location: ' . option('base_uri') . 'gauth/login/');
  }
}

/*
 * fsl_gauth_logout
 *
 * unsets google token and returns to base URL or URL of choice
 *
 * @string (string) String to be decrypted
 * @key (string) OPTIONAL encryption key to use. If not provided default
 *     key specified with option('global_encryption_key', 'setyourkeyhere') config
 * @return (string)
 */

/* 
 *
 * fsl_hash_create
 *
 * creates a one way sha256 hash. Good for storing passwords, keys, and other data
 * elements where you do not need to unencrypt
 *
 * @string (string) data to be hashed
 * @return (string)
 */
function fsl_hash_create($string)
{
  return Password::create_hash($string);
}

/* 
 *
 * fsl_hash_validate
 *
 * verify that a string matches a stored hashed version of the string
 *
 * @string (string) data to be validated
 * @good_hash (string) hash to be compared against
 * @return (boolean)
 */
function fsl_hash_validate($string,$good_hash)
{
  return Password::validate_password($string, $good_hash);
}


/* 
 *
 * fsl_curl
 *
 * make an external http call. helpful when calling external api's
 *
 * @url: url of api
 * @method: action of request. Options include GET POST PUT DELETE
 * @datatype: expected data either XML or JSON or FORM supported. Otherwise defaults to *
 * @urlparams: url parameters (query string)
 * @postdata: array of data to submit
 * @authtype: authentication if needed BASIC or TOKEN (bearer token)
 * @$authuser: basic auth user
 * @$authpassword: basic auth password
 * @$authtoken: bearer token
 * @$customheader: ARRAY of custom headers
 * output: return array(http response code, curl info, response);
 */

function fsl_curl(
    string $url,
    string $method = "GET",
    ?string $datatype = null,
    ?string $urlparams = null,
    mixed $postdata = null,
    ?string $authtype = null,
    ?string $authuser = null,
    ?string $authpassword = null,
    ?string $authtoken = null,
    ?array $customheader = null
): array {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        throw new InvalidArgumentException('Invalid URL provided');
    }

    $ch = curl_init();
    
    // Secure defaults
    curl_setopt_array($ch, [
        CURLOPT_URL => $urlparams ? $url . '?' . $urlparams : $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,  // Always verify SSL certificates
        CURLOPT_SSL_VERIFYHOST => 2,     // Strict SSL checking
        CURLOPT_TIMEOUT => 30,           // Reasonable timeout
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        CURLOPT_FOLLOWLOCATION => false, // Don't follow redirects by default
    ]);
    
    //set user agent
    $headers = array('User-Agent: Fresh Squeezed Limonade (https://github.com/yesinteractive/fsl)');

    //data type
    if ($datatype == "XML") {
        array_push($headers,'Content-Type: application/xml');    
    }else if ($datatype == "JSON") {
        array_push($headers,'Content-Type: application/json');  
    }  else if ($datatype == "FORM") {
        array_push($headers,'Content-Type: application/x-www-form-urlencoded');
    } else {
        array_push($headers,'Content-Type: */*');      
    }

    //method
    if ($method == "POST") {
        //need to post the values? 
        curl_setopt($ch, CURLOPT_POST, true);
        //fields which will be posted. 
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
    } else if ($method == "PUT") {
        curl_setopt($ch, CURLOPT_PUT, true);
    } else if ($method == "DELETE") {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else{
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
    }
    
    //auth
    if ($authtype == "BASIC") {
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($ch, CURLOPT_USERPWD, "$authuser:$authpassword");
    } else if ($authtype == "TOKEN") {
        array_push($headers,'Authorization: Bearer ' . $authtoken);
    } else{
        //no auth
    }
    
    //merge headeer arrays if customheader set and set headers 
    if ($customheader == NULL){
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); 
    } else {
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($headers,$customheader)); 
    }               
                
    $output = curl_exec($ch);
    $info = curl_getinfo($ch);
    $code = $info['http_code'];
    curl_close($ch);

    return $ret = array($code, $info, $output);
}


?>