<?php

namespace Crypto;

/**
 * Simple wrapper for php mcrypt.
 *
 * @version 1.1
 * @author Vladimir Kovpak <cn007b@gmail.com>
 * @see https://github.com/codeName007/crypto
 */
class Crypto
{
    const CIPHER = MCRYPT_RIJNDAEL_128;
    const MODE   = MCRYPT_MODE_CBC;

    private $key;

    /**
     * Crypto constructor.
     *
     * @param string $key Key with which the data will be encrypted.
     * @throws \InvalidArgumentException When key not string or empty.
     */
    public function __construct($key)
    {
        if (!is_string($key)) {
            throw new \InvalidArgumentException('Key should be string.');
        }
        if (empty($key) || $key===null || !isset($key)) {
            throw new \InvalidArgumentException("Key can't be empty.");
        }
        $this->key = $key;
    }

    /**
     * Encrypts data.
     *
     * @param string $text Data to be encrypted.
     * @throws \InvalidArgumentException When $text not string.
     * @return string Encrypted data.
     */
    public function encrypt($text)
    {
        if (!is_string($text)) {
            throw new \InvalidArgumentException('Text should be string.');
        }

        if (empty($text)|| !isset($text) || $text==='' || $text===null) {
            throw new \InvalidArgumentException("text can't be empty.");
        }
        $ivSize = mcrypt_get_iv_size(self::CIPHER, self::MODE);
        $iv = mcrypt_create_iv($ivSize, MCRYPT_DEV_RANDOM);
        $encryptedData = mcrypt_encrypt(self::CIPHER, $this->key, $text, self::MODE, $iv);
        return base64_encode($iv.$encryptedData);
    }

    /**
     * Decrypts data.
     *
     * @param string $encryptedData Data to be decrypted.
     * @throws \InvalidArgumentException When $encryptedData not string.
     * @throws \RuntimeException When iv initialization failed.
     * @return string Decrypted data.
     */
    public function decrypt($encryptedData)
    {
        if (!is_string($encryptedData)) {
            throw new \InvalidArgumentException('Encrypted data should be string.');
        }
        if (empty($encryptedData) || $encryptedData==='' || $encryptedData===null) {
            throw new \InvalidArgumentException("encryptedData can't be empty.");
        }
        $encryptedData = base64_decode($encryptedData);
        $ivSize = mcrypt_get_iv_size(self::CIPHER, self::MODE);
        if (strlen($encryptedData) < $ivSize) {
            throw new \RuntimeException('IV initialization failed.');
        }
        $iv = substr($encryptedData, 0, $ivSize);
        $encryptedData = substr($encryptedData, $ivSize);
        $text = mcrypt_decrypt(self::CIPHER, $this->key, $encryptedData, self::MODE, $iv);
        return rtrim($text, "\0");
    }
}
