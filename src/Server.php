<?php

namespace Hihaowen\SSO;

/**
 * SSO服务
 *
 * Class Server
 * @package Services\SSO
 *
 * @author  haowenzhi <haowenzhi@cmcm.com>
 */
abstract class Server
{
    use TokenHelper;

    /**
     * facade 方式退出登录
     */
    protected function onLogout($brokerId, $token)
    {
        $response = [];

        // 清空 server session
        $sessionId = $this->storage()->get('sso_broker_' . $brokerId . '_' . $token);
        if ( empty($sessionId) ) {
            throw new SSOException('获取服务端session_id失败');
        }

        if ( session_status() === PHP_SESSION_ACTIVE ) {
            throw new SSOException('session 已经启动了');
        }

        session_id($sessionId);
        session_start();

        unset($_SESSION['login_id'], $_SESSION['login_name']);

        // 清空 brokers cache、server session cache、通知各个 broker 退出
        $brokerTokens = $this->storage()->sMembers('sso_brokers_' . $sessionId);
        if ( !empty($brokerTokens) ) {
            // 清空cache、通知各个 broker 退出
            foreach ($brokerTokens as $brokerToken) {
                $this->storage()->del('sso_broker_' . $brokerToken);

                $brokerInfo = explode('_', $brokerToken);

                $brokerId = $brokerInfo[0] ?? '';

                $token = $brokerInfo[1] ?? '';

                if ( empty($brokerId) || empty($token) ) {
                    continue;
                }

                $syncUrl   = $this->brokers()[$brokerId]['sync_url'] ?? '';
                $secret    = $this->brokers()[$brokerId]['secret'] ?? '';
                $urlParams = [
                    'command'   => 'logout',
                    'broker_id' => $brokerId,
                    'token'     => $token,
                    'check_sum' => $this->generateSum($brokerId, $secret, $token),
                ];

                $response['script_src'][] = $syncUrl . '?' . http_build_query($urlParams);
            }

            $this->storage()->del('sso_brokers_' . $sessionId);
        }

        return $response;
    }

    /**
     * facade 方式获取用户信息
     */
    protected function onUser($brokerId, $token)
    {
        $response = [];

        // 清空 server session
        $sessionId = $this->storage()->get('sso_broker_' . $brokerId . '_' . $token);
        if ( empty($sessionId) ) {
            throw new SSOException('获取服务端session_id失败');
        }

        if ( session_status() === PHP_SESSION_ACTIVE ) {
            throw new SSOException('session 已经启动了');
        }

        session_id($sessionId);
        session_start();

        $response['login_id']   = $_SESSION['login_id'];
        $response['login_name'] = $_SESSION['login_name'];

        return $response;
    }

    /**
     * 登录
     *
     * @param LoginUserContext $loginUserContext
     */
    public function login(LoginUserContext $loginUserContext)
    {
        $response = [];

        // 登录用户
        $loginId = $loginUserContext->loginId();
        if ( empty($loginId) ) {
            throw new SSOException('未登录');
        }

        // 开启会话
        if ( session_status() != PHP_SESSION_ACTIVE ) {
            session_start();
        }

        $sessionId = session_id();

        // brokers session cache & sync brokers login
        foreach ($this->brokers() as $brokerId => $broker) {
            // 新生成用户在 broker 上的token
            $token = $this->generateBrokerToken($brokerId);

            // 保存登录用户在 broker 上的 token
            $tokenCacheSuffixKey = $brokerId . '_' . $token;
            $this->storage()->set('sso_broker_' . $tokenCacheSuffixKey, $sessionId);

            // 便于通过 session_id 反查用户在 broker 上的 token
            $this->storage()->sAdd('sso_brokers_' . $sessionId, $tokenCacheSuffixKey);

            $syncUrl   = $this->brokers()[$brokerId]['sync_url'] ?? '';
            $secret    = $this->brokers()[$brokerId]['secret'] ?? '';
            $urlParams = [
                'command'   => 'login',
                'broker_id' => $brokerId,
                'token'     => $token,
                'check_sum' => $this->generateSum($brokerId, $secret, $token),
            ];

            $response['script_src'][] = $syncUrl . '?' . http_build_query($urlParams);
        }

        $_SESSION['login_id']   = $loginUserContext->loginId();
        $_SESSION['login_name'] = $loginUserContext->loginName();

        $response['login_id']   = $_SESSION['login_id'];
        $response['login_name'] = $_SESSION['login_name'];

        return $response;
    }

    /**
     * 提供对外 broker 暴露的方法
     *
     * @param       $command
     * @param array $params
     *
     * @return mixed
     * @throws SSOException
     */
    public function facade($command, $params)
    {
        if ( !in_array($command, ['logout', 'user']) ) {
            throw new SSOException('不支持的命令: ' . $command);
        }

        // 验签
        $token    = $params['token'] ?? '';
        $brokerId = $params['broker_id'] ?? '';
        $checkSum = $params['check_sum'] ?? '';
        $secret   = $this->brokers()[$brokerId]['secret'] ?? '';

        if ( !$this->checkSum($brokerId, $secret, $token, $checkSum) ) {
            throw new SSOException('验签失败');
        }

        $method = 'on' . ucfirst($command);

        return $this->$method($brokerId, $token);
    }

    /**
     * @return Storage
     */
    abstract public function storage(): Storage;

    /**
     * broker 配置信息
     *
     * @return array
     */
    abstract public function brokers(): array;
}
