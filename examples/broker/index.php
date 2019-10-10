<?php

require_once __DIR__ . '/../../vendor/autoload.php';

$broker = new \Hihaowen\SSO\Broker(
    getenv('SSO_GATEWAY'),
    getenv('SSO_BROKER_ID'),
    getenv('SSO_SECRET'),
    getenv('SSO_LOGIN_URL')
);

print_r($broker->user());
