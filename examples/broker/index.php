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

    $loginUrl  = $_SERVER['SSO_LOGIN_URL'] . '?'
        . http_build_query([
            'return_url' => urlencode($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['SERVER_NAME']),
        ]);

    $action = $_REQUEST['action'] ?? '';

    if ( !empty($_REQUEST['command']) ) { // 处理服务端发来的请求
        $broker->facade($_REQUEST['command'], $_REQUEST);
    } elseif ( $action === 'logout' ) {
        $broker->logout();
        echo 'ok';
        exit;
    } else { // 显示当前用户信息
        $loginId   = $broker->user()->loginId();
        $loginName = $broker->user()->loginName();
    }
} catch (\Hihaowen\SSO\NeedLoginException $e) { // 登录
    header('Location: ' . $loginUrl, true, 307);
    exit;
} catch (\Exception $e) {
    echo 'unknown error: ', $e->getMessage(), ', code: ', $e->getCode();
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>用户中心</title>

    <!-- Bootstrap core CSS -->
    <link href="https://v4.bootcss.com/docs/4.3/dist/css/bootstrap.css" rel="stylesheet">

    <style>
        .bd-placeholder-img {
            font-size: 1.125rem;
            text-anchor: middle;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
        }

        @media (min-width: 768px) {
            .bd-placeholder-img-lg {
                font-size: 3.5rem;
            }
        }
    </style>
    <script src="https://cdn.staticfile.org/jquery/2.1.1/jquery.min.js"></script>
    <script type="text/javascript">
        $(document).ready(function () {
            $("button").click(function () {
                $.post("/?action=logout", {},
                    function (data, status) {
                        if (data == 'ok' && status == 'success') {
                            self.location.href = "<?php echo $loginUrl; ?>";
                        } else {
                            alert('网络错误');
                            self.location.reload();
                        }
                    }, 'text'
                );
            });
        });
    </script>
</head>
<body>
<div class="container">
    <div class="jumbotron mt-3">
        <h1><?php echo $loginName; ?></h1>
        <p class="lead">登录ID <?php echo $loginId; ?></p>
        <button class="btn btn-lg btn-primary" role="button">退出 &raquo;</button>
    </div>
</div>
</body>
</html>