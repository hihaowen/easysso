<?php

namespace Hihaowen\SSO;

/**
 * Class LoginUser
 * @package Hihaowen\SSO
 *
 * @author  haowenzhi <haowenzhi@cmcm.com>
 */
class LoginUser implements LoginUserContext
{
    private $name = null;

    private $id = null;

    public function setLoginName($name)
    {
        $this->name = $name;
    }

    public function setLoginId($id)
    {
        $this->id = $id;
    }

    public function loginName()
    {
        return $this->name;
    }

    public function loginId()
    {
        return $this->id;
    }

    public function check()
    {
        // TODO: Implement check() method.
    }
}
