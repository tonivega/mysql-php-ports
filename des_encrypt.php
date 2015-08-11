<?php
/*
 * Ciphers a cleartext with TripleDES CBC using the same procedure as mySQL.
 * Ciphertexts from this function can be deciphered with mysql's "des_decrypt()" function.
 *
 * @category   Security, Mysql
 * @author     Antonio Vega Alvarez <user toni.vega at host gmail with tld com>
 * @license    MIT License
 * @version    1.0
 * @see        Mysql source code.
 * @since      2015-08-10
 */
function mysql_des_encrypt($cleartext, $password) {
    $keyLen = 24; // DES_EDE_KEY_SZ
    $ivLen = 8;  // DES_IV_SZ

    $D = [];
    $D[0] = '';

    // avega: Key and IV derivation from password.
    //D_i = HASH(D_(i-1) || data || salt)
    for ($i = 1; ($keyLen + $ivLen) >= strlen(implode('', $D)); $i++) {
        $D[$i] = hex2bin(md5($D[$i - 1] . $password));
    }

    $derivedBytes = implode('', $D);

    $derivedKey = substr($derivedBytes, 0, 24);

    // avega: pitfall warning 1 -> mysql implementation discards the derived IV, 8 bytes of zeros are used instead.
    //$derivedIV = substr($derivedBytes,24,8);
    $derivedIV = hex2bin('0000000000000000');

    // avega: pitfall warning 2 -> custom padding is needed for 8 bytes alignment
    $fillCount = (8 - (strlen($cleartext) % 8)) ;

    $paddingFill = '';
    for($i = 0; $i < $fillCount - 1; $i++){
        $paddingFill .= '*';
    }

    // avega: string length is needed (because of alignment of 8 bytes)
    $cleartext .=  $paddingFill . pack("h", $fillCount);

    // avega: mysql adds a prefix for password/key source definition.
    $prefix = hex2bin('FF');

    // avega: pitfall warning 3 -> use OPENSSL_ZERO_PADDING instead OPENSSL_RAW_DATA, also returns BASE64 ...
    $ciphertext = $prefix . base64_decode(openssl_encrypt($cleartext, 'des-ede3-cbc', $derivedKey, OPENSSL_ZERO_PADDING, $derivedIV));

    return $ciphertext;
}

$cleartext = 'random string random string';
$password  = 'changeme';

$ciphertext = mysql_des_encrypt($cleartext, $password);

echo 'Result : ' . bin2hex($ciphertext) . PHP_EOL;
