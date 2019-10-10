<?php

namespace Hihaowen\SSO;

/**
 * 存储协商
 *
 * Interface Storage
 * @package Services\SSO
 */
interface Storage
{
    /**
     * @param $key
     *
     * @return string
     */
    public function get($key): string;

    /**
     * @param $key
     * @param $value
     *
     * @return mixed
     */
    public function set($key, $value);

    /**
     * @param $key
     *
     * @return mixed
     */
    public function del($key);

    /**
     * @param $key
     * @param $member
     *
     * @return mixed
     */
    public function sAdd($key, $member);

    /**
     * @param $key
     *
     * @return mixed
     */
    public function sMembers($key);
}
