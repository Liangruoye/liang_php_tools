<?php

//弯弯的
class AspireAes
{

    private static $instance = null;

    public static function getInstance($key = '0123456789abcdef0123456789abcdef', $iv = '0123456789abcdef0123456789abcdef')
    {
        return new AspireAes ($key, $iv);
    }

    /**
     * 将$text格式化，使其长度为$blocksize整数倍
     *
     * @param string $text
     * @param int $blocksize
     *
     * @return string
     */
    private function pkcs5Pad($text, $blocksize)
    {
        //计算需要增加的字节数
        $pad = $blocksize - (strlen($text) % $blocksize);
        //在text后面加入字符串
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * 去掉$text后面因格式化而加入的多余字符串
     *
     * @param unknown_type $text
     *
     * @retrurn stirng
     */
    private function pkcs5Unpad($text)
    {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text))
            return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
            return false;
        return substr($text, 0, -1 * $pad);
    }

    private function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64url_decode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    private $key = null, $iv = null;

    private function __construct($key, $iv)
    {
        $this->key = pack('H*', $key);
        $this->iv = pack('H*', $iv);
    }

    public function encrypt($str, $encode = 'base64')
    {
        $str = self::pkcs5Pad($str, 16);
        $str = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $str, MCRYPT_MODE_CBC, $this->iv);
        switch ($encode) {
            case 'hex' :
                $str = bin2hex($str);
                break;
            case 'base64' :
                $str = base64_encode($str);
                break;
            case 'base64url' :
                $str = $this->base64url_encode($str);
                break;
        }
        return $str;
    }

    /**
     * 解密浏览器端用AES128加密过的数据
     *
     * @param string $str
     *
     * @return string
     */
    public function decrypt($str, $encode = 'base64')
    {
        switch ($encode) {
            case 'hex' :
                $str = pack('H*', $str);
                break;
            case 'base64' :
                $str = base64_decode($str);
                break;
            case 'base64url' :
                $str = $this->base64url_decode($str);
                break;
        }
        $str = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $str, MCRYPT_MODE_CBC, $this->iv);
        $str = self::pkcs5Unpad($str);
        return $str;
    }

    public static function example()
    {
        $aes = self::getInstance();
        $txt = 'JCE中支持AES，支持的模式和填充方式JCE中AES支持五中模式：CBC，CFB，ECB，OFB，PCBC；支持三种填充：NoPadding，PKCS5Padding，ISO10126Padding。不支持SSL3Padding。不支持“NONE”模式';
        $x = $aes->encrypt($txt);
        echo "加密：$txt\r\n\r\n$x\r\n\r\n";

        $txt = $x;
        $x = $aes->decrypt($txt);
        echo "解密：$txt\t\t$x\r\n";
    }

    /**生成指定长度的可见字符串
     *
     * @param int $length
     */
    public static function getRandStr($length = 16)
    {
        $s = '';
        for ($i = 0; $i < $length; $i++) {
            $s .= chr(mt_rand(32, 126));
        }
        return $s;
    }

}
//AspireAes::example();


//网上的
class CryptAES
{
    protected $cipher = MCRYPT_RIJNDAEL_128;
    protected $mode = MCRYPT_MODE_ECB;
    protected $pad_method = NULL;
    protected $secret_key = '';
    protected $iv = '';

    public function set_cipher($cipher)
    {
        $this->cipher = $cipher;
    }

    public function set_mode($mode)
    {
        $this->mode = $mode;
    }

    public function set_iv($iv)
    {
        $this->iv = $iv;
    }

    public function set_key($key)
    {
        $this->secret_key = $key;
    }

    public function require_pkcs5()
    {
        $this->pad_method = 'pkcs5';
    }

    protected function pad_or_unpad($str, $ext)
    {
        if ( is_null($this->pad_method) )
        {
            return $str;
        }
        else
        {
            $func_name = __CLASS__ . '::' . $this->pad_method . '_' . $ext . 'pad';
            if ( is_callable($func_name) )
            {
                $size = mcrypt_get_block_size($this->cipher, $this->mode);
                return call_user_func($func_name, $str, $size);
            }
        }
        return $str;
    }

    protected function pad($str)
    {
        return $this->pad_or_unpad($str, '');
    }

    protected function unpad($str)
    {
        return $this->pad_or_unpad($str, 'un');
    }

    public function encrypt($str)
    {
        $str = $this->pad($str);
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');

        if ( empty($this->iv) )
        {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        }
        else
        {
            $iv = $this->iv;
        }

        mcrypt_generic_init($td, $this->secret_key, $iv);
        $cyper_text = mcrypt_generic($td, $str);
        $rt=base64_encode($cyper_text);
        //$rt = bin2hex($cyper_text);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $rt;
    }

    public function decrypt($str){
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');

        if ( empty($this->iv) )
        {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        }
        else
        {
            $iv = $this->iv;
        }

        mcrypt_generic_init($td, $this->secret_key, $iv);
        //$decrypted_text = mdecrypt_generic($td, self::hex2bin($str));
        $decrypted_text = mdecrypt_generic($td, base64_decode($str));
        $rt = $decrypted_text;
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $this->unpad($rt);
    }

    public static function hex2bin($hexdata) {
        $bindata = '';
        $length = strlen($hexdata);
        for ($i=0; $i < $length; $i += 2)
        {
            $bindata .= chr(hexdec(substr($hexdata, $i, 2)));
        }
        return $bindata;
    }

    public static function pkcs5_pad($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    public static function pkcs5_unpad($text)
    {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text)) return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
        return substr($text, 0, -1 * $pad);
    }
}