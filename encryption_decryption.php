<?php

function _application_crypt( $string, $action = 'e' ) {
    $secret_key = 'thisismysecretkey@123';
    $secret_iv = '!@#$%^&*';

    $output = false;
    $encrypt_method = "AES-256-CBC";
    $key = hash( 'sha256', $secret_key );
    $iv = substr( hash( 'sha256', $secret_iv ), 0, 16 );

    if( $action == 'e' ) {
        $output = base64_encode( openssl_encrypt( $string, $encrypt_method, $key, 0, $iv ) );
    }
    else if( $action == 'd' ){
        $output = openssl_decrypt( base64_decode( $string ), $encrypt_method, $key, 0, $iv );
    }

    return $output;
}

echo "Encrypted: ". $encrypt = _application_crypt("arnabroy",'e');
echo "<br/> Decrypted: ". $decrypt = _application_crypt($encrypt,'d');
?>