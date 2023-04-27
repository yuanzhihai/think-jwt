<?php

return [
    'login_type'             => env( 'JWT_LOGIN_TYPE','mpop' ), //  登录方式，sso为单点登录，同一个用户只能登录一个端，mpop为多点登录
    /**
     * 单点登录自定义数据中必须存在uid的键值，这个key你可以自行定义，只要自定义数据中存在该键即可
     */
    'sso_key'                => 'uid',
    /**
     * 只能用于Hmac包下的加密非对称算法，其它的都会使用公私钥
     */
    'secret'                 => env( 'JWT_SECRET','yzh52521' ),
    /**
     * JWT 权限keys
     * 对称算法: HS256, HS384 & HS512 使用 `JWT_SECRET`.
     * 非对称算法: RS256, RS384 & RS512 / ES256, ES384 & ES512 使用下面的公钥私钥，需要自己去生成.
     */
    'keys'                   => [
        'public'     => env( 'JWT_PUBLIC_KEY' ), // 公钥，例如：'file:///path/to/public/key'
        'private'    => env( 'JWT_PRIVATE_KEY' ), // 私钥，例如：'file:///path/to/private/key'

        /**
         * 你的私钥的密码。不需要密码可以不用设置
         */
        'passphrase' => env( 'JWT_PASSPHRASE' ),
    ],
    'ttl'                    => env( 'JWT_TTL',7200 ), // token过期时间，单位为秒
    /**
     * 支持的对称算法：HS256、HS384、HS512
     * 支持的非对称算法：RS256、RS384、RS512、ES256、ES384、ES512
     */
    'alg'                    => env( 'JWT_ALG','HS256' ), // jwt的hearder加密算法
    /**
     * jwt使用到的缓存前缀
     * 建议使用独立的redis做缓存，这样比较好做分布式
     */
    'cache_prefix'           => 'yzh52521:think-jwt',

    /**
     * 是否开启黑名单，单点登录和多点登录的注销、刷新使原token失效，必须要开启黑名单，目前黑名单缓存只支持webman缓存驱动
     */
    'blacklist_enabled'      => env( 'JWT_BLACKLIST_ENABLED',true ),

    /**
     * 黑名单的宽限时间 单位为：秒，注意：如果使用单点登录，该宽限时间无效
     */
    'blacklist_grace_period' => env( 'JWT_BLACKLIST_GRACE_PERIOD',0 ),
    /**
     * 签发者
     */
    'issued_by'              => 'think-jwt',
    /**
     * 区分不同场景的token，比如你一个项目可能会有多种类型的应用接口鉴权,下面自行定义，我只是举例子
     * 下面的配置会自动覆盖根配置，比如app会里面的数据会覆盖掉根数据
     * 下面的scene会和根数据合并
     * scene必须存在一个default
     * 什么叫根数据，这个配置的一维数组，除了scene都叫根配置
     */
    'scene'                  => [
        'default' => [
            'secret'     => 'default',   // 非对称加密使用字符串,请使用自己加密的字符串
            'login_type' => 'mpop',      //  登录方式，sso为单点登录，mpop为多点登录
            'sso_key'    => 'uid',
            'ttl'        => 7200,        // token过期时间，单位为秒
            'user_model' => function () { //用户模型 为一个匿名函数，默认返回空数组，可以根据自己定制返回模型
                return [];
            },
        ],
        'app'    => [
            'secret'     => 'app',       // 非对称加密使用字符串,请使用自己加密的字符串
            'login_type' => 'sso',        //  登录方式，sso为单点登录，mpop为多点登录
            'sso_key'    => 'uid',
            'ttl'        => 7200,          // token过期时间，单位为秒
            'user_model' => function () {  //用户模型 为一个匿名函数，默认返回空数组，可以根据自己定制返回模型
                return [];
            },
        ]
    ]
];
