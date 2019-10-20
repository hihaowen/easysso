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

        return $this->destroyLoginSession($sessionId);
    }

    private function destroyLoginSession($sessionId)
    {
        $response = [];

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
        $loginSessionKey = 'sso_broker_' . $brokerId . '_' . $token;
        $sessionId       = $this->storage()->get($loginSessionKey);
        if ( empty($sessionId) ) {
            throw new NeedLoginException('获取服务端session_id(' . $loginSessionKey . ')失败');
        }

        if ( session_status() === PHP_SESSION_ACTIVE ) {
            throw new NeedLoginException('session 已经启动了');
        }

        session_id($sessionId);
        session_start();

        if ( empty($_SESSION['login_id']) || empty($_SESSION['login_name']) ) {
            throw new NeedLoginException('用户信息已过期');
        }

        $response['login_id']   = $_SESSION['login_id'];
        $response['login_name'] = $_SESSION['login_name'];

        return $response;
    }

    /**
     * 服务端获取当前登录用户信息
     *
     * @return LoginUserContext
     */
    public function user(): LoginUserContext
    {
        // 开启会话
        if ( session_status() != PHP_SESSION_ACTIVE ) {
            session_start();
        }

        $loginUser = new LoginUser();

        // 未登录
        if ( empty($_SESSION['login_id']) ) {
            return $loginUser;
        }

        $loginUser->setLoginId($_SESSION['login_id']);
        $loginUser->setLoginName($_SESSION['login_name']);

        return $loginUser;
    }

    public function logout()
    {
        // 开启会话
        if ( session_status() != PHP_SESSION_ACTIVE ) {
            session_start();
        }

        unset($_SESSION['login_id'], $_SESSION['login_name']);

        return $this->destroyLoginSession(session_id());
    }

    /**
     * 登录
     *
     * @param LoginUserContext $loginUserContext
     */
    public function login(LoginUserContext $loginUserContext, $returnUrl = null)
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
        $response['return_url'] = $returnUrl;

        return $response;
    }

    /**
     * 通知单个Broker登录
     *
     * @param      $brokerId
     * @param null $returnUrl
     *
     * @return array
     * @throws SSOException
     */
    public function syncOneBrokerLogin($brokerId, $returnUrl = null)
    {
        // 开启会话
        if ( session_status() != PHP_SESSION_ACTIVE ) {
            session_start();
        }

        // 同步登录状态
        $sessionId = session_id();

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

        $response = [];

        $response['script_src'][] = $syncUrl . '?' . http_build_query($urlParams);
        $response['login_id']     = $_SESSION['login_id'];
        $response['login_name']   = $_SESSION['login_name'];
        $response['return_url']   = $returnUrl;

        return $response;
    }

    /**
     * 验证返回url是否合法
     *
     * @param $originReturnUrl
     *
     * @return bool
     */
    private function checkReturnUrl($originReturnUrl)
    {
        if ( empty($originReturnUrl) ) {
            return true;
        }

        $originHost = parse_url($originReturnUrl, PHP_URL_HOST);
        if ( !$originHost ) {
            return false;
        }

        $self = $_SERVER['SERVER_NAME'];
        if ( $originHost === $self ) {
            return true;
        }

        $isValid = false;

        foreach ($this->brokers() as $broker) {
            if ( empty($broker['host']) ) {
                continue;
            }
            if ( $originHost === $broker['host'] ) {
                $isValid = true;
                break;
            }
        }

        return $isValid;
    }

    /**
     * 初始化 Broker 请求参数
     *
     * @param array $params
     *
     * @return array
     * @throws SSOException
     */
    public function initBrokerParams(array $params)
    {
        // 验证来源
        $returnUrl = $params['return_url'] ?? null;
        $returnUrl = urldecode($returnUrl);
        if ( !$this->checkReturnUrl($returnUrl) ) {
            throw new SSOException('请求来源不合法');
        }

        // 验签
        $token    = $params['token'] ?? '';
        $brokerId = $params['broker_id'] ?? '';
        $checkSum = $params['check_sum'] ?? '';
        $secret   = $this->brokers()[$brokerId]['secret'] ?? '';
        if ( !$this->checkSum($brokerId, $secret, $token, $checkSum) ) {
            throw new SSOException('验签失败');
        }

        return [
            'token'      => $token,
            'broker_id'  => $brokerId,
            'check_sum'  => $checkSum,
            'secret'     => $secret,
            'return_url' => $returnUrl,
        ];
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

        $method = 'on' . ucfirst($command);

        return $this->$method($params['broker_id'], $params['token']);
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
