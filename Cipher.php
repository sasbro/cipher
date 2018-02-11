<?php
/**
* Cipher is a Class to en-/decode (binary) a given value with initialization vector and given encryption key
*
* Encode example usage:
* try{
*     $cipher = new Cipher();
*     $cipher->set_key('56aa54fa11be8b46afcc9042059d06c630844a77965ed7152c13faedf30ad0a6');
*
*     $encodedArray = $cipher->encode(array(
*         'Value 1',
*         'Value 2'
*     );
*
*     // store returned values in DB
*     $value_1 = $encodedArray['data'][0];
*     $value_2 = $encodedArray['data'][1];
*     $iv = (binary) $encodedArray['iv']; // without IV you cant decode
* }
*     catch (Exception $e){
*     // $log->lwrite($e->getMessage());
* }
*
* Decode example usage:
* try{
*     $cipher = new Cipher();
*     $cipher->set_key('56aa54fa11be8b46afcc9042059d06c630844a77965ed7152c13faedf30ad0a6');
*
*     // get stored binary values from DB (e.g. value 1)
*
*     $decodedArray = array();
*     parse_str($cipher->decode([binary value from DB], [IV from DB]), $decodedArray); 
* }
*     catch (Exception $e){
*     // $log->lwrite($e->getMessage());
* }
* 
* @package  Example
* @author   Sascha Bröning <sascha.broening@gmail.com>
* @version  1.0
* @access   public
*/

class Cipher {

    /**
     * given encryption key for en-/decode values
     * @var string
     */
    private $encryptionKey = '';
    /**
     * store values during encryption and for later response
     * @var array
     */
    private $encodedArray = array();

    /**
     * unset stored encryption key
     */
    public function __destruct() 
    {
        unset($this->encryptionKey);
    }

    /**
     * set initialized encryption key
     * 
     * @param string $value stores encryption key
     */
    public function set_key($value) 
    { 
        $this->encryptionKey = $value;
    }

    /**
     * Pad the data to block size
     * 
     * @param  string $data data for later encryption
     * @param  int    $size blocksize
     * @return string data adapted to block size
     */
    private function pad($data, $size)
    {
        $length = $size - strlen($data) % $size;
        return $data . str_repeat(chr($length), $length);
    }

    /**
     * Unpad data
     * 
     * @param  string $data committed decrypted string
     * @return string unpad and return committed string
     */
    private function unpad($data)
    {
        return substr($data, 0, -ord($data[strlen($data) - 1]));
    }

    /**
     * Generate a pseudo-random string of x bytes for the initialization vector to add randomness to the encryption
     * 
     * @param  integer $length number of bytes
     * @return string returns a string of pseudo-random bytes
     */
    private function get_pseudo_bytes($length = 16)
    {
        return openssl_random_pseudo_bytes($length, $strong);
    }

    /**
     * Create either a URI coded query string or a URI coded string (depends on input)
     * 
     * @param  mixed $data committed value
     * @return string URI coded
     */
    private function prepare_data($data)
    {
        return is_array($data) ? http_build_query($data) : urlencode($data);
    }

    /**
     * Encode commited value into binary value and initilization vector
     * 
     * @param  mixed $data committed value to encode
     * @return array encoded value and initilization vector for later decode purpose
     */
    public function encode($data)
    {
        $iv = $this->get_pseudo_bytes();

        if(is_array($data))
        {
            foreach($data as $row)
            {
                $string = $this->prepare_data($row);

                $enc_str = openssl_encrypt(
                    $this->pad($string, 16),
                    'AES-256-CBC',
                    $this->encryptionKey,
                    0,   
                    $iv            
                );
                array_push($this->encodedArray, $enc_str);
            }
        }

        return array('data' => $this->encodedArray, 'iv' => $iv);
    }

    /**
     * Decode commited value
     * 
     * @param  array $encodedArray value to decode
     * @param  binary $iv initilization vector for decode use
     * @return string decoded string
     */
    public function decode($encodedArray, $iv)
    {
        $decodedStr = $this->unpad(openssl_decrypt(
            $encodedArray,
            'AES-256-CBC',
            $this->encryptionKey,
            0,
            $iv
        ));

        return $decodedStr;
    }
}
