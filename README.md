# Crypto
Simple wrapper for php mcrypt.

#### Install
Via composer: `composer require crypto/crypto`.

#### Usage
````php
<?php

use Crypto\Crypto;

$crypto = new Crypto('secret key');
$text = 'Shaken not stirred!';
$encryptedString = $crypto->encrypt($text);
$decryptedString = $crypto->decrypt($encryptedString);
````
