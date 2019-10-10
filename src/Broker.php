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

    private $ssoUrl;

    use TokenHelper;

    /**
     * Broker constructor.
     *
     * @param      $gateway
     * @param      $brokerId
     * @param      $secret
     * @param null $ssoUrl
     */
    public function __construct($gateway, $brokerId, $secret, $ssoUrl = null)
    {
        $this->gateway  = $gateway;
        $this->brokerId = $brokerId;
        $this->secret   = $secret;
        $this->ssoUrl   = $ssoUrl;

        if ( !$this->token ) {
            header('Location: ' . $ssoUrl, 302);
            exit;
        }

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
        parse_str($params, $paramsArr);

        $brokerId = $paramsArr['broker_id'];
        $token    = $paramsArr['token'];
        $checkSum = $paramsArr['check_sum'];

        if ( !$this->generateSum($brokerId, $this->secret, $token) === $checkSum ) {
            throw new SSOException('错误的签名');
        }

        setcookie($this->getCookieName($this->brokerId), $token);
    }

    /**
     * 服务端退出登录同步调用
     */
    protected function syncLogout($params)
    {
        parse_str($params, $paramsArr);

        $brokerId = $paramsArr['broker_id'];
        $token    = $paramsArr['token'];
        $checkSum = $paramsArr['check_sum'];

        if ( !$this->generateSum($brokerId, $this->secret, $token) === $checkSum ) {
            throw new SSOException('错误的签名');
        }

        setcookie($this->getCookieName($this->brokerId), null);
    }

    /**
     * 提供对外暴露的方法
     *
     * @param        $command
     * @param string $params
     *
     * @return mixed
     * @throws SSOException
     */
    public function facade($command, $params)
    {
        if ( !in_array($command, ['logout', 'logout']) ) {
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
        if ( empty($this->token) ) {
            throw new SSOException('未登录');
        }

        $res = $this->request('user', [
            'broker_id' => $this->brokerId,
            'token'     => $this->token,
            'check_sum' => $this->generateSum($this->brokerId, $this->secret, $this->token),
        ]);

        if ( $res['status'] != 200 ) {
            throw new SSOException('获取失败, code: ' . $res['status']);
        }

        return json_decode($res['response'], true);
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

        return true;
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
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 2);

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

        return [
            'status'   => curl_getinfo($ch, CURLINFO_HTTP_CODE),
            'response' => $response,
        ];
    }
}
