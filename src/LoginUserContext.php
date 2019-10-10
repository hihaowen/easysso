<?php

namespace Hihaowen\SSO;

/**
 * 登录用户相关
 *
 * Interface LoginUserContext
 * @package Services\SSO
 */
interface LoginUserContext
{
    /**
     * 登录验证
     *
     * @return mixed
     */
    public function check();

    /**
     * 登录用户ID
     *
     * @return int
     */
    public function loginId();

    /**
     * 登录名
     *
     * @return string|null
     */
    public function loginName();

    /**
     * @param $id
     *
     * @return mixed
     */
    public function setLoginId($id);

    /**
     * @param $name
     *
     * @return mixed
     */
    public function setLoginName($name);
}
