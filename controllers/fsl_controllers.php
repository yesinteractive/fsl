<?php

/*
*
*   Sample controller functions showcased on FSL Launch Page
*
*/

function process_time(){
   $time = number_format( microtime(true) - LIM_START_MICROTIME, 6);
  return("<BR>Controller Function Called: " .  option('routecallback') . "<BR>Request processed in $time seconds");
}

  function hello_world()
  {
    
    fsl_session_set('crop','Yummy Limonade');
    set_or_default('name', params('who'), "everybody");
    $time = number_format( microtime(true) - LIM_START_MICROTIME, 6);
   
    return html("Session Data Set: Yummy Limonade<BR>". process_time());
  }

/*
*
* This is an example on how to create and decode JWT Tokens
*
*/

  function jwt()
  {
   $token = array();
   $token['id'] = "test123";
   $token['name'] = "FSL";
   $testjwt =  fsl_jwt_encode($token, "testkey");
   $jwtdecode = fsl_jwt_decode($testjwt,"testkey");
   $time = number_format( microtime(true) - LIM_START_MICROTIME, 6); 
    return html("Token To Encode: " . $token['id'] ." <BR>Key: testkey<BR>JWT: $testjwt<BR>Decoded JWT: " . $jwtdecode->id . "<BR>". process_time());
  }

/*
*
* This is an example on how to execute a http call. Good for calling other microservices
*
*/

  function curl()
  {
 
    $response = fsl_curl('http://dadjokes.online/echo', "GET", "JSON", "test=test", NULL,  "TOKEN", NULL, NULL, "321", NULL ); 
    $jsonData = json_encode( json_decode($response[2]), JSON_PRETTY_PRINT |  JSON_UNESCAPED_SLASHES);
    return html("Response Code: " . $response[0] ." <BR>Response:<font color=yellow> " . $jsonData ." </font><BR>". process_time());
  }

/*
*
* This is an example on how to execute a http call. Good for calling other microservices
*
*/

  function create_hash()
  {
 
    
    $response = fsl_hash_create("my_password");
    $validate = fsl_hash_validate("my_password","$response");
    
    if ($validate == TRUE) $valid =  "true";
    else $valid = "false";
    
    return html("String to Hash: 'my_password' <BR>Hash Created: $response <BR>Response when running hash against 'my_password': $valid <BR>". process_time());
  }

/*
*
* This is an example on how to make a RESTful JSON Response and Set A Status Code
*
*/

  function api()
  {
    $arr = array('a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5);
   // status(202); //returns HTTP status code of 202
    status(202); //returns HTTP status code of 202
    return json($arr);
  }


function showip()
  {
    $ip = $_SERVER['REMOTE_ADDR'];
    set_or_default('name', params('who'), "everybody");

    //session data example

    $session = (empty(fsl_session_check('crop'))) ? "No session exists" : fsl_session_check('crop');

    //Encryption Example
    $estring = fsl_encrypt($session);
    $dstring = fsl_decrypt($estring);
    
    
  
    return html("Your IP is $ip.<BR>Your session data: $session. <BR>Session Data encrypted.<BR>Encrypt session data: $estring<BR>Session Data decrypted.<BR>Decrypted session data: $dstring <BR>" . process_time());
  } 

 function kill_session()
  {
    set_or_default('name', params('who'), "everybody");
    session_destroy();
    return html("Session Is Destroyed.<BR>" . process_time());
  }

 function welcome()
  {
    set_or_default('name', params('name'), "everybody");    
    return html("html_welcome");
  }

 function are_you_ok($name = null)
  {
    if(is_null($name))
    {
      $name = params('name');
      if(empty($name)) halt(NOT_FOUND, "Undefined name.");

    }
    set('name', $name);
    return html("Are you ok $name ?<BR>". process_time());
  }

 function how_are_you()
  {
    $name = params('name');
    if(empty($name)) halt(NOT_FOUND, "Undefined name.");
    # you can call an other controller function if you want
    if(strlen($name) < 4) return are_you_ok($name);
    set('name', $name);
    return html("I hope you are fine, $name.<BR>". process_time());
  }

 function image_show()
  {
    $ext = file_extension(params('name'));
    $filename = option('public_dir')."/".basename(params('name'), ".$ext");
    if(params('size') == 'thumb') $filename .= ".thb";
    $filename .= '.jpg';
 
    if(!file_exists($filename)) halt(NOT_FOUND, "$filename doesn't exists");
    render_file($filename);
  }

 function image_show_jpeg_only()
  {
    $ext = file_extension(params(0));
    $filename = option('public_dir').params(0);
    if(params('size') == 'thumb') $filename .= ".thb";
    $filename .= '.jpg';
  
    if(!file_exists($filename)) halt(NOT_FOUND, "$filename doesn't exists");
    render_file($filename);
  }

?>