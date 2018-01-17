<?php

/**
 * 获取当前页面完整URL地址
 */
function get_url()
{
    $sys_protocal = isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == '443' ? 'https://' : 'http://';
    $php_self = $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];
    $path_info = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '';
    $relate_url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : $php_self.(isset($_SERVER['QUERY_STRING']) ? '?'.$_SERVER['QUERY_STRING'] : $path_info);
    $url = $sys_protocal.(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '').$relate_url;
    /*if(substr($url, -1) != '/')
    {
        $url = $url.'/';
    }*/
    return $url;
}

/**
 * 获取客户端IP地址(TP3.2)
 * @param integer $type 返回类型 0 返回IP地址 1 返回IPV4地址数字
 * @param boolean $adv 是否进行高级模式获取（有可能被伪装）
 * @return mixed
 */
function get_client_ip($type = 0,$adv=false) {
    $type       =  $type ? 1 : 0;
    static $ip  =   NULL;
    if ($ip !== NULL) return $ip[$type];
    if($adv){
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $arr    =   explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $pos    =   array_search('unknown',$arr);
            if(false !== $pos) unset($arr[$pos]);
            $ip     =   trim($arr[0]);
        }elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip     =   $_SERVER['HTTP_CLIENT_IP'];
        }elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip     =   $_SERVER['REMOTE_ADDR'];
        }
    }elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip     =   $_SERVER['REMOTE_ADDR'];
    }
    // IP地址合法验证
    $long = sprintf("%u",ip2long($ip)); //将ip转化为无符号的整数
    $ip   = $long ? array($ip, $long) : array('0.0.0.0', 0);
    return $ip[$type];
}

/**
 * 发送HTTP状态
 * @param integer $code 状态码
 * @return void
 */
function send_http_status($code) {
    static $_status = array(
        // Informational 1xx
        100 => 'Continue',
        101 => 'Switching Protocols',
        // Success 2xx
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        // Redirection 3xx
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Moved Temporarily ',  // 1.1
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        // 306 is deprecated but reserved
        307 => 'Temporary Redirect',
        // Client Error 4xx
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        // Server Error 5xx
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
        509 => 'Bandwidth Limit Exceeded'
    );
    if(isset($_status[$code])) {
        header('HTTP/1.1 '.$code.' '.$_status[$code]);
        // 确保FastCGI模式下正常
        header('Status:'.$code.' '.$_status[$code]);
    }
}

// 不区分大小写的in_array实现
function in_array_case($value,$array){
    return in_array(strtolower($value),array_map('strtolower',$array));
}

// 敏感词过滤
function filter_bad_word($content, $path, $dilimiter=',', $fill='***')
{
    $bad_word_res = fopen($path, 'r') or die('failed to open file!');
    $bad_word_str = fgets($bad_word_res);
    fclose($bad_word_res);
    $bad_word_arr = explode($dilimiter, $bad_word_str);
    $bad_word_arr = array_combine($bad_word_arr, array_fill(0, count($bad_word_arr), $fill));
    $content = strtr($content, $bad_word_arr);
    return $content;
}

/*比file_get_contents稳定的多！$timeout为超时时间，单位是秒，默认为1s。
* 保留原file_get_contents函数的原因是当读取本地文件时，用原生的file_get_contents显然更合适
* $ctx = stream_context_create(array(
    'http' => array(
    'timeout' => 1 //设置一个超时时间，单位为秒
    )
    )
    );
    file_get_contents("http://example.com/", 0, $ctx); // 给file_get_contents设置超时时间
*/
function curl_get_contents($url,$timeout=1) {
    $curlHandle = curl_init();
    curl_setopt( $curlHandle , CURLOPT_URL, $url );
    curl_setopt( $curlHandle , CURLOPT_RETURNTRANSFER, 1 );
    curl_setopt( $curlHandle , CURLOPT_TIMEOUT, $timeout );
    $result = curl_exec( $curlHandle );
    curl_close( $curlHandle );
    return $result;
}

/*
 * 数据库防sql注入
 */
function getSafeInputText($s) {
    if (is_array ( $s )) {
        foreach ( $s as $k => $v ) {
            $s [$k] = $this->getSafeInputText( $v );
        }
    } else {
        $s = trim ( $s );
        if (preg_match ( '/^\w+$/', $s )) {
            //仅包含字母、数字、下划线的字符无法构造注入语义
            return $s;
        }
        $forbiden = null;
        $toReplace = null;
        if ($forbiden == null) {
            /****避免跨站漏洞和SQL注入，将半角转成全角使注入失效或者注入后代码因语法错误而无法执行**/
            //XSS:转义<>使用户无法在html代码中拼凑脚本;
            // &&可用来增加查询条件，如搜索用户时猜测用户密码等
            // || 可用来使查询条件为真，使其它限制条件失效，如造成任意密码均可登录等
            // # 用来注释掉后面的SQL片段
            //转义括号使其无法js或mysql调用函数，转义引号和\使其无法拼凑js脚本或SQL语句
            $forbiden = array ('<', '>', '"', "'", '\\', '(', ')', '&&', '||', '#' );
            $toReplace = array ('＜', '＞', '＂', "＇", '＼', '（', '）', '＆＆', '｜｜', '＃' );
        }
        $s = str_replace ( $forbiden, $toReplace, $s );

        /********************以下用来反制针对整数的注入(如：where uid=$uid)*******************************/
        //危险关键字之前需要有空白字符或/**/等才能形成 注入
        if (preg_match ( '/(\s+|(\/\*.*\*\/)+)(and|or|union|outfile)/i', $s )) {
            //将可能导致SQL注入的字符串变成全角，使注入后的SQL产生语法错误。
            $s = str_ireplace ( array ('and', 'or', 'union', 'outfile' ), array ('ａnd', 'ｏr', 'ｕnion', 'ｏutfile' ), $s );
        }
        //mysql注释语法之一 两个减号后面跟至少一个空白字符,主要危害数字类型的属性:SELECT * FROM ts_user WHERE id=23-- and passwd=md5('123456')
        if (preg_match ( '/(--\s+)|(--$)/', $s )) {
            $s = str_replace ( '--', '－－', $s );
        }
    }
    return $s;
}

/*
 * 判断数值在二维数组里是否存在
 */
function deep_in_array($value, $array) {
    foreach($array as $item) {
        if(!is_array($item)) {
            if ($item == $value) {
                return true;
            } else {
                continue;
            }
        }

        if(in_array($value, $item)) {
            return true;
        } else if(deep_in_array($value, $item)) {
            return true;
        }
    }
    return false;
}

/*
 * 二维数组的排序
 */
function area_order($arr,$keys,$type='asc') {
    $keysvalue = $new_array = array();
    foreach ($arr as $k=>$v) {
        $keysvalue[$k] = $v[$keys];
    }
    if ($type == 'asc') {
        asort($keysvalue);
    } else {
        arsort($keysvalue);
    }
    reset($keysvalue);
    foreach ($keysvalue as $k=>$v) {
        $new_array[$k] = $arr[$k];
    }
    return $new_array;
}

/*
 * 判断数组的维数
 */
function getmaxdim($arr) {
    if (!is_array($arr)) {
        return 0;
    } else {
        $dimension = 0;
        foreach ($arr as $item1) {
            $t1 = getmaxdim($item1);
            if ($t1>$dimension) {$dimension = $t1;}
        }
        return $dimension+1;
    }
}

/*
 * 根据经纬度算距离
 */
function distance($lat1, $lng1, $lat2, $lng2, $miles = true) {
    $pi80 = M_PI / 180;
    $lat1 *= $pi80;
    $lng1 *= $pi80;
    $lat2 *= $pi80;
    $lng2 *= $pi80;
    $r = 6372.797; // mean radius of Earth in km
    $dlat = $lat2 - $lat1;
    $dlng = $lng2 - $lng1;
    $a = sin($dlat / 2) * sin($dlat / 2) + cos($lat1) * cos($lat2) * sin($dlng / 2) * sin($dlng / 2);
    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
    $km = $r * $c;
    return ($miles ? ($km * 0.621371192) : $km);
}