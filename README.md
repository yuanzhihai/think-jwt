### 说明：

> `think-jwt` 支持多应用单点登录、多应用多点登录、多应用支持注销 token(token会失效)、支持多应用刷新 token

> 多应用单点登录：在该应用配置下只会有一个 token 生效，一旦刷新 token ，前面生成的 token 都会失效，一般以用户 id 来做区分

> 多应用多点登录：在该配置应用下token 不做限制，一旦刷新 token ，则当前配置应用的 token 会失效

> 注意：使用多应用单点登录或者多应用多点登录时，必须要开启黑名单，并且使用 `thinkphp` 的缓存(建议使用 `redis` 缓存)
> 。如果不开启黑名单，无法使 token 失效，生成的 token 会在有效时间内都可以使用(未更换证书或者 secret )。

> 多应用单点登录原理：`JWT` 有七个默认字段供选择。单点登录主要用到 jti 默认字段，`jti` 字段的值默认为缓存到redis中的key(
> 该key的生成为场景值+存储的用户id(`sso_key`))
> ，这个key的值会存一个签发时间，token检测会根据这个时间来跟token原有的签发时间对比，如果token原有时间小于等于redis存的时间，则认为无效

> 多应用多点登录原理：多点登录跟单点登录差不多，唯一不同的是jti的值不是场景值+用户id(`sso_key`)
> ，而是一个唯一字符串，每次调用 `refreshToken` 来刷新 `token` 或者调用 `logout` 注销 token 会默认把请求头中的 token
> 加入到黑名单，而不会影响到别的 token

> token 不做限制原理：token 不做限制，在 token 有效的时间内都能使用，你只要把配置文件中的 `blacklist_enabled`
> 设置为 `false` 即可，即为关闭黑名单功能

### 使用：

```shell
composer require yzh52521/think-jwt
```

##### jwt配置

```php
<?php
return [
   
    'login_type' => env('JWT_LOGIN_TYPE', 'mpop'), //  登录方式，sso为单点登录，mpop为多点登录

    /**
     * 单点登录自定义数据中必须存在uid的键值，这个key你可以自行定义，只要自定义数据中存在该键即可
     */
    'sso_key' => 'uid',

    /**
     * 只能用于Hmac包下的加密非对称算法，其它的都会使用公私钥
     */
    'secret' => env('JWT_SECRET', 'yzh52521'),

    /**
     * JWT 权限keys
     * 对称算法: HS256, HS384 & HS512 使用 `JWT_SECRET`.
     * 非对称算法: RS256, RS384 & RS512 / ES256, ES384 & ES512 使用下面的公钥私钥，需要自己去生成.
     */
    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'), // 公钥，例如：'file:///path/to/public/key'
        'private' => env('JWT_PRIVATE_KEY'), // 私钥，例如：'file:///path/to/private/key'

        /**
         * 你的私钥的密码。不需要密码可以不用设置
         */
        'passphrase' => env('JWT_PASSPHRASE'),
    ],

    'ttl' => env('JWT_TTL', 7200), // token过期时间，单位为秒

    /**
     * 支持的对称算法：HS256、HS384、HS512
     * 支持的非对称算法：RS256、RS384、RS512、ES256、ES384、ES512
     */
    'alg' => env('JWT_ALG', 'HS256'), // jwt的hearder加密算法

    /**
     * jwt使用到的缓存前缀
     * 建议使用独立的redis做缓存，这样比较好做分布式
     */
    'cache_prefix' => 'think-jwt',

    /**
     * 是否开启黑名单，单点登录和多点登录的注销、刷新使原token失效，必须要开启黑名单，目前黑名单缓存只支持thinkphp缓存驱动
     */
    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /**
     * 黑名单的宽限时间 单位为：秒，注意：如果使用单点登录，该宽限时间无效
     */
    'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', 0),

    /**
     * 签发者
     */
    'issued_by' => 'think-jwt',

    /**
     * 区分不同场景的token，比如你一个项目可能会有多种类型的应用接口鉴权,下面自行定义，我只是举例子
     * 下面的配置会自动覆盖根配置，比如app会里面的数据会覆盖掉根数据
     * 下面的scene会和根数据合并
     * scene必须存在一个default
     * 什么叫根数据，这个配置的一维数组，除了scene都叫根配置
     */
    'scene' => [
        'default' => [
             'secret' => 'default',  // 非对称加密使用字符串,请使用自己加密的字符串
             'login_type' => 'mpop', //  登录方式，sso为单点登录，mpop为多点登录
             'sso_key' => 'uid',
             'ttl' => 7200,         // token过期时间，单位为秒,
             'user_model'=>''       //用户模型 为一个匿名函数，默认返回空数组，可以根据自己定制返回模型
        ],
        'app' => [
            'secret' => 'app',     // 非对称加密使用字符串,请使用自己加密的字符串
            'login_type' => 'sso',  //  登录方式，sso为单点登录，mpop为多点登录
            'sso_key' => 'uid',
            'ttl' => 7200,           // token过期时间，单位为秒
            'user_model'=>function(){ //用户模型 为一个匿名函数，默认返回空数组，可以根据自己定制返回模型
                return [];
            } 
        ],
    ]
];
```

##### 全局路由验证 app/middleware.php

```shell
<?php
return [
     yzh52521\Jwt\Middleware\JWTAuthDefaultSceneMiddleware:class,
];
```

##### 局部验证

在 `route/app.php` 文件中，想要验证的路由加入 `jwt` 验证中间件即可，例如：

```shell
<?php

Route::group('/v1', function () {
    Route::get('/getToken', 'index/getToken']);
})->middleware(\yzh52521\Jwt\Middleware\JWTAuthDefaultSceneMiddleware::class);
```

##### 7、模拟登录获取token,具体情况下面的例子文件

```shell
<?php

namespace app\controller;
use yzh52521\Jwt\JWT;

class Index
{
    # 模拟登录,获取token
    public function login(Request $request,Jwt $jwt)
    {
        $username = $request->param('username');
        $password = $request->param('password');
        if ($username && $password) {
            $userData = [
                'uid' => 1, // 如果使用单点登录，必须存在配置文件中的sso_key的值，一般设置为用户的id
                'username' => 'xx',
            ];
            // 使用默认场景登录
            $token = $jwt->getToken('default', $userData);
            $data = [
                'code' => 0,
                'msg' => 'success',
                'data' => [
                    'token' => $token->toString(),
                    'expires_in' => $jwt->getTTL($token->toString()),
                ]
            ];
            return json($data);
        }
        return json(['code' => 0, 'msg' => '登录失败', 'data' => []]);
    }

    # http头部必须携带token才能访问的路由
    public function getToken()
    {
        return json(['code' => 0, 'msg' => 'success', 'data' => ['a' => 1]]);
    }
}
```

##### 路由

```shell
<?php
# 登录
Route::post('/login', 'index/login');

# 获取数据
Route::group('/v1', function () {
    Route::get('/getToken', 'index/getToken');
})->middleware(yzh52521\Jwt\Middleware\JWTAuthDefaultSceneMiddleware::class);
```

##### 鉴权

在需要鉴权的接口,请求该接口时在 `HTTP` 头部加入

```shell
Authorization  Bearer token
```

##### 结果

###### 请求：/login，下面是返回的结果

```shell
{
    "code": 0,
    "msg": "获取token成功",
    "data": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NjQ3MzgyNTgsIm5iZiI6MTU2NDczODI1OCwiZXhwIjoxNTY0NzM4MzE4LCJ1aWQiOjEsInVzZXJuYW1lIjoieHgifQ.CJL1rOqRmrKjFpYalY6Wu7JBH6vkbysfvOf-TMQgonQ"
    }
}
```

###### 请求：/v1/getToken

```shell
{
    "code": 0,
    "msg": "success",
    "data": {
        "a": 1
    }
}
```

##### 10、例子文件

```php
<?php

namespace app\controller;

use yzh52521\Jwt\JWT;
use yzh52521\Jwt\Util\JWTUtil;
class Index
{
    /**
     *
     * @Inject
     * @var JWT
     */
    protected $jwt;

    
    
    public function __construct()
    {
        $this->jwt =JWT::class;
    }


    /**
     * 模拟登录 default场景
     */
    public function login(Request $request)
    {
        $username = $request->param('username');
        $password = $request->param('password');
        if ($username && $password) {
            $userData = [
                'uid' => 1, // 如果使用单点登录，必须存在配置文件中的sso_key的值，一般设置为用户的id
                'username' => 'xx',
            ];
            // 使用默认场景登录
            $token = $this->jwt->getToken('default', $userData);
            $data = [
                'code' => 0,
                'msg' => 'success',
                'data' => [
                    'token' => $token->toString(),
                    'expires_in' => $this->jwt->getTTL($token->toString()),
                ]
            ];
            return json($data);
        }
        return json(['code' => 0, 'msg' => '登录失败', 'data' => []]);
    }

    /**
     * 模拟登录 app场景
     */
    public function loginApp(Request $request)
    {
        $username = $request->param('username');
        $password = $request->param('password');
        if ($username && $password) {
            $userData = [
                'uid' => 1, // 如果使用单点登录，必须存在配置文件中的sso_key的值，一般设置为用户的id
                'username' => 'xx',
            ];
            // 使用application2场景登录
            $token = $this->jwt->getToken('app', $userData);
          
            $data = [
                'code' => 0,
                'msg' => 'success',
                'data' => [
                    [
                        'token' => $token->toString(),
                        'expires_in' => $this->jwt->getTTL($token1->toString()),
                        'dynamic_exp' => $this->jwt->getTokenDynamicCacheTime($token->toString())
                    ]
                ]
            ];
            return json($data);
        }
        return json(['code' => 0, 'msg' => '登录失败', 'data' => []]);
    }

  

 

    /**
     * default 场景的刷新token
     */
    public function refreshDefaultToken(Request $request)
    {
        $token = $this->jwt->refreshToken();
        $data = [
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'token' => $token->toString(),
                'expires_in' => $this->jwt->getTTL($token->toString()),
            ]
        ];
        return json($data);
    }

    /**
     * application 场景的刷新token
     *
     */
    public function refreshAppToken(Request $request)
    {
        $token = $this->jwt->refreshToken();
        $data = [
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'token' => $token->toString(),
                'expires_in' => $this->jwt->getTTL($token->toString()),
            ]
        ];
        return json($data);
    }

  

    /**
     * default 场景的删除token
     */
    public function logout_default()
    {
        return $this->jwt->logout();
    }

    /**
     * app 场景的删除token
     *
     */
    public function logout_app()
    {
        return $this->jwt->logout();
    }

  

    /**
     * 只能使用default场景值生成的token访问
     */
    public function getDefaultData(Request $request)
    {
        $data = [
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'dynamic_exp' => $this->jwt->getTokenDynamicCacheTime(JWTUtil::getToken($request)),
                'jwt_claims' => JWTUtil::getParserData($request)
            ]
        ];
        return json($data);
    }

    /**
     * 只能使用app场景值生成的token访问
     */
    public function getAppData(Request $request)
    {
        $data = [
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'dynamic_exp' => $this->jwt->getTokenDynamicCacheTime(JWTUtil::getToken($request)),
                'jwt_claims' => JWTUtil::getParserData($request)
            ]
        ];
        return json($data);
    }


}

```

#### user_model 用户模型 
```php
'user_model' => function($uid) {
    return \think\facade\Db::table('user')
        ->field('id,username,create_time')
        ->where('id',$uid)
        ->find();
}
```

##### 获取解析后的 token 数据

提供了一个 `getParserData` 来获取解析后的 token 数据。
例如：`JWTUtil::getParserData($this->request)`

##### 如何支持每个场景生成的token不能互相访问各个应用

具体你可以查看
yzh52521\Jwt\Middleware\JWTAuthSceneDefaultMiddleware
yzh52521\Jwt\Middleware\JWTAuthSceneAppMiddleware
这两个中间件，根据这两个中间件你可以编写自己的中间件来支持每个场景生成的token不能互相访问各个应用

##### 建议

> 目前 `jwt` 抛出的异常目前有两种类型
> `yzh52521\Jwt\Exception\TokenValidException`、    
> `yzh52521\Jwt\Exception\JWTException`  
> 异常为 `TokenValidException` 验证失败的异常，会抛出 `401` ,   
> `JWTException` 异常会抛出 `400`，   
> 最好你们自己在项目异常重新返回错误信息


