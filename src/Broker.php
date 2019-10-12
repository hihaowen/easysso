<?php

namespace Hihaowen\SSO;

/**
 * SSO服务调用方
 *
 * Class Broker
 * @package Services\SSO
 *
 * @author  haowenzhi <haowenzhi@cmcm.com>
 */
class Broker
{
    private $gateway;

    private $brokerId;

    private $secret;

    private $token;

    private $ssoLoginUrl;

    use TokenHelper;

    /**
     * Broker constructor.
     *
     * @param      $gateway
     * @param      $brokerId
     * @param      $secret
     * @param null $ssoLoginUrl
     */
    public function __construct($gateway, $brokerId, $secret, $ssoLoginUrl = null)
    {
        $this->gateway     = $gateway;
        $this->brokerId    = $brokerId;
        $this->secret      = $secret;
        $this->ssoLoginUrl = $ssoLoginUrl;

        $this->token = null;
        if ( isset($_COOKIE[$this->getCookieName($this->brokerId)]) ) {
            $this->token = $_COOKIE[$this->getCookieName($this->brokerId)];
        }
    }

    /**
     * @param $params
     *
     * @throws SSOException
     */
    protected function syncLogin($params)
    {
        $brokerId = $params['broker_id'];
        $token    = $params['token'];
        $checkSum = $params['check_sum'];

        if ( !$this->generateSum($brokerId, $this->secret, $token) === $checkSum ) {
            throw new SSOException('错误的签名');
        }

        header('P3P: CP="CURa ADMa DEVa PSAo PSDo OUR BUS UNI PUR INT DEM STA PRE COM NAV OTC NOI DSP COR"');

        setcookie($this->getCookieName($this->brokerId), $token);
    }

    /**
     * 服务端退出登录同步调用
     */
    protected function syncLogout($params)
    {
        $brokerId = $params['broker_id'];
        $token    = $params['token'];
        $checkSum = $params['check_sum'];

        if ( !$this->generateSum($brokerId, $this->secret, $token) === $checkSum ) {
            throw new SSOException('错误的签名');
        }

        header('P3P: CP="CURa ADMa DEVa PSAo PSDo OUR BUS UNI PUR INT DEM STA PRE COM NAV OTC NOI DSP COR"');

        setcookie($this->getCookieName($this->brokerId), null);
    }

    /**
     * 提供对外暴露的方法
     *
     * @param        $command
     * @param array  $params
     *
     * @return mixed
     * @throws SSOException
     */
    public function facade($command, array $params)
    {
        if ( !in_array($command, ['login', 'logout']) ) {
            throw new SSOException('不支持的命令: ' . $command);
        }

        $method = 'sync' . ucfirst($command);

        return $this->$method($params);
    }

    /**
     * 登录用户信息
     *
     * @return LoginUserContext
     */
    public function user(): LoginUserContext
    {
        if ( !$this->token ) {
            throw new NeedLoginException('未登录: ' . $this->ssoLoginUrl, 302);
        }

        $res = $this->request('user', [
            'broker_id' => $this->brokerId,
            'token'     => $this->token,
            'check_sum' => $this->generateSum($this->brokerId, $this->secret, $this->token),
        ]);

        if ( $res['status'] != 200 ) {
            throw new SSOException('获取失败, code: ' . $res['status']);
        }

        $loginId   = $res['response']['login_id'] ?? null;
        $loginName = $res['response']['login_name'] ?? null;

        $loginUser = new LoginUser();
        $loginUser->setLoginId($loginId);
        $loginUser->setLoginName($loginName);

        return $loginUser;
    }

    /**
     * 退出登录
     */
    public function logout()
    {
        if ( empty($this->token) ) {
            throw new SSOException('未登录');
        }

        $res = $this->request('logout', [
            'broker_id' => $this->brokerId,
            'token'     => $this->token,
            'check_sum' => $this->generateSum($this->brokerId, $this->secret, $this->token),
        ]);

        if ( $res['status'] != 200 ) {
            throw new SSOException('获取失败, code: ' . $res['status']);
        }

        return $res['response'] ?? [];
    }

    /**
     * 向服务端发起请求
     *
     * @param $command
     * @param $params
     *
     * @return mixed
     * @throws SSOException
     */
    private function request($command, array $params)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // set timeout
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 1000);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 2000);

//        curl_setopt($ch, CURLOPT_HTTPHEADER, [
//            'SSO_TOKEN' => $token,
//        ]);
        curl_setopt($ch, CURLOPT_URL, $this->gateway);

        // post method
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, [
                'command' => $command,
            ] + $params);

        // 允许抓取请求的header
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);

        $response = curl_exec($ch);

        if ( curl_errno($ch) ) {
            throw new \RuntimeException('请求失败: ' . curl_error($ch));
        }

        if ( empty($response) || !is_string($response) ) {
            throw new SSOException('返回数据为空或格式错误');
        }

        // json格式
        $response = json_decode($response, true);
        $errorNo  = $response['errno'] ?? 1;
        $error    = $response['error'] ?? '';
        $data     = $response['data'] ?? [];
        if ( $errorNo != 0 ) {
            throw new SSOException('调用错误: ' . $error);
        }

        return [
            'status'   => curl_getinfo($ch, CURLINFO_HTTP_CODE),
            'response' => $data,
        ];
    }
}
