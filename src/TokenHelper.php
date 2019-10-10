<?php

namespace Hihaowen\SSO;

trait TokenHelper
{
    /**
     * 生成 Broker 使用的 Token
     *
     * @param $brokerId
     *
     * @return string
     */
    public function generateBrokerToken($brokerId): string
    {
        return md5(uniqid($brokerId . '.' . mt_rand()));
    }

    /**
     * 生成完整性签名
     *
     * @param $brokerId
     * @param $secret
     * @param $token
     *
     * @return string
     */
    public function generateSum($brokerId, $secret, $token): string
    {
        return hash('sha256', $brokerId . $secret . $token);
    }

    /**
     * 验证参数
     *
     * @param $brokerId
     * @param $token
     * @param $sum
     *
     * @return bool
     */
    public function checkSum($brokerId, $secret, $token, $sum): bool
    {
        return $this->generateSum($brokerId, $secret, $token) === $sum;
    }

    public function getCookieName($brokerId)
    {
        return 'sso_user_' . $brokerId;
    }
}
