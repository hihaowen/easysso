<?php

ini_set('display_errors', 'on');
error_reporting(E_ALL);

require_once __DIR__ . '/../../vendor/autoload.php';

try {
    $broker = new \Hihaowen\SSO\Broker(
        $_SERVER['SSO_GATEWAY'],
        $_SERVER['SSO_BROKER_ID'],
        $_SERVER['SSO_SECRET'],
        $_SERVER['SSO_LOGIN_URL']
    );

    $action = $_REQUEST['action'] ?? '';

    if ( !empty($_REQUEST['command']) ) { // 处理服务端发来的请求
        $broker->facade($_REQUEST['command'], $_REQUEST);
    } elseif ( $action === 'logout' ) {
        var_dump($broker->logout());
    } else { // 显示当前用户信息
        var_dump($broker->user()->loginName());
    }
} catch (\Exception $e) {
    echo 'error: ', $e->getMessage(), ', code: ', $e->getCode();
}
