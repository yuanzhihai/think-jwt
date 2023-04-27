<?php
declare( strict_types = 1 );

namespace yzh52521\Jwt;

use DateTimeImmutable;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Psr\SimpleCache\CacheInterface;
use think\Cache;
use think\Request;
use yzh52521\Jwt\Constant\JWTConstant;
use yzh52521\Jwt\Exception\JWTException;
use yzh52521\Jwt\Exception\TokenValidException;
use yzh52521\Jwt\Util\JWTUtil;
use yzh52521\Jwt\Util\TimeUtil;

class JWT extends AbstractJWT
{
    private $supportAlgs = [
        // 非对称算法
        'RS256' => 'Lcobucci\JWT\Signer\Rsa\Sha256',
        'RS384' => 'Lcobucci\JWT\Signer\Rsa\Sha384',
        'RS512' => 'Lcobucci\JWT\Signer\Rsa\Sha512',
        'ES256' => 'Lcobucci\JWT\Signer\Ecdsa\Sha256',
        'ES384' => 'Lcobucci\JWT\Signer\Ecdsa\Sha384',
        'ES512' => 'Lcobucci\JWT\Signer\Ecdsa\Sha512',

        // 对称算法
        'HS256' => 'Lcobucci\JWT\Signer\Hmac\Sha256',
        'HS384' => 'Lcobucci\JWT\Signer\Hmac\Sha384',
        'HS512' => 'Lcobucci\JWT\Signer\Hmac\Sha512',
    ];

    /**
     * @var string
     */
    private $jwtClaimScene = 'jwt_scene';

    private $scene = 'default';

    /**
     * @var Request
     */
    public Request $request;

    /**
     * @var mixed|CacheInterface
     */
    private $cache;

    /**
     * @var array
     */
    private $jwtConfig;

    /**
     * @var Configuration
     */
    private $lcobucciJwtConfiguration;


    public function __construct()
    {
        $config = config( 'jwt' );
        $scenes = $config['scene'];
        foreach ( $scenes as $key => $scene ) {
            $sceneConfig           = array_merge( $config,$scene );
            $this->jwtConfig[$key] = $sceneConfig;
        }
        $this->cache   = app( 'cache' );
        $this->request = app( 'request' );
    }

    /**
     * @param string $scene
     * @return $this
     */
    protected function initConfiguration(string $scene)
    {
        $this->setScene( $scene );
        $jwtSceneConfig = $this->getJwtSceneConfig( $scene );
        if (empty( $jwtSceneConfig )) {
            throw new JWTException( "The jwt scene [{$this->getScene()}] not found",400 );
        }
        $this->buildConfig();
        return $this;
    }

    /**
     * 生成token
     *
     * @param array $claims
     * @return Token|string
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function getToken(string $scene,array $claims): Plain
    {
        // 初始化lcobucci jwt config
        $this->initConfiguration( $scene );
        $claims[$this->jwtClaimScene] = $scene; // 加入场景值

        $jwtSceneConfig = $this->getJwtSceneConfig();
        $loginType      = $jwtSceneConfig['login_type'];
        $ssoKey         = $jwtSceneConfig['sso_key'];
        $issuedBy       = $jwtSceneConfig[RegisteredClaims::ISSUER] ?? 'think-jwt';
        if ($loginType == JWTConstant::MPOP) { // 多点登录,场景值加上一个唯一id
            $uniqid = uniqid( $this->getScene().':',true );
        } else { // 单点登录
            if (empty( $claims[$ssoKey] )) {
                throw new JWTException( "There is no {$ssoKey} key in the claims",400 );
            }
            $uniqid = $this->getScene().":".$claims[$ssoKey];
        }

        $clock     = SystemClock::fromUTC();
        $now       = $clock->now();
        $expiresAt = $this->getExpiryDateTime( $now,$jwtSceneConfig['ttl'] );
        $builder   = $this->lcobucciJwtConfiguration->builder( ChainedFormatter::withUnixTimestampDates() )->issuedBy( $issuedBy );
        foreach ( $claims as $k => $v ) {
            if ($k == RegisteredClaims::SUBJECT) {
                $builder = $builder->relatedTo( $v );
                continue;
            }
            if ($k == RegisteredClaims::AUDIENCE) {
                if (!is_array( $v )) {
                    throw new JWTException( "Aud only supports array types",400 );
                }
                $builder = $builder->PermittedFor( ...$v );
                continue;
            }
            if ($k == RegisteredClaims::ISSUER) {
                $builder = $builder->issuedBy( $v );
                continue;
            }
            $builder = $builder->withClaim( $k,$v ); // 自定义数据
        }
        $builder = $builder
            // Configures the id (jti claim) 设置jwt的jti
            ->identifiedBy( $uniqid )
            // Configures the time that the token was issue (iat claim) 发布时间
            ->issuedAt( $now )
            // Configures the time that the token can be used (nbf claim) 在此之前不可用
            ->canOnlyBeUsedAfter( $now )
            // Configures the expiration time of the token (exp claim) 到期时间
            ->expiresAt( $expiresAt );


        $token = $builder->getToken( $this->lcobucciJwtConfiguration->signer(),$this->lcobucciJwtConfiguration->signingKey() );
        if ($loginType == JWTConstant::SSO) {
            $this->addTokenBlack( $token );
        }
        return $token;
    }

    protected function getExpiryDateTime($now,$ttl): DateTimeImmutable
    {
        return $now->modify( "+{$ttl} second" );
    }

    /**
     * 获取当前场景的配置
     *
     * @return mixed
     */
    public function getJwtSceneConfig(string $scene = null)
    {
        if ($scene == null) {
            return $this->jwtConfig[$this->getScene()];
        }
        return $this->jwtConfig[$scene];
    }

    /**
     * @param string $token
     * @return bool
     */
    public function verifyToken(string $token): bool
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        $token = $this->tokenToPlain( $token );
        $this->initConfiguration( $this->getSceneByTokenPlain( $token ) );

        $constraints = $this->validationConstraints( $token->claims(),$this->lcobucciJwtConfiguration );
        if (!$this->lcobucciJwtConfiguration->validator()->validate( $token,...$constraints )) {
            throw new TokenValidException( 'Token authentication does not pass',400 );
        }

        // 验证token是否存在黑名单
        if ($this->hasTokenBlack( $token )) {
            throw new TokenValidException( 'Token authentication has expired',400 );
        }

        return true;
    }

    /**
     * @param string $scene
     * @param string $token
     * @return bool
     */
    public function verifyTokenAndScene(string $scene,string $token): bool
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }
        $plainToken = $this->tokenToPlain( $token );
        $tokenScene = $this->getSceneByTokenPlain( $plainToken );
        if ($scene != $tokenScene) {
            throw new JWTException( 'The token does not support the current scene',400 );
        }

        return $this->verifyToken( $token );
    }


    /**
     * 判断token是否已经加入黑名单
     *
     * @param Plain $claims
     * @return bool
     */
    public function hasTokenBlack(Plain $token): bool
    {
        $sceneConfig = $this->getSceneConfigByToken( $token );
        if ($sceneConfig['blacklist_enabled']) {
            $claims     = $token->claims();
            $cacheKey   = $this->getCacheKey( $sceneConfig,$claims->get( RegisteredClaims::ID ) );
            $cacheValue = $this->cache->get( $cacheKey );
            if ($cacheValue == null) {
                return true;
            }
            if ($sceneConfig['login_type'] == JWTConstant::MPOP) {
                return !empty( $cacheValue['valid_until'] ) && !TimeUtil::isFuture( $cacheValue['valid_until'] );
            }

            if ($sceneConfig['login_type'] == JWTConstant::SSO) {
                // 签发时间
                $iatTime = TimeUtil::getCarbonTimeByTokenTime( $claims->get( RegisteredClaims::ISSUED_AT ) )->getTimestamp();
                if (!empty( $cacheValue['valid_until'] ) && !empty( $iatTime )) {
                    // 当前token的签发时间小于等于缓存的签发时间，则证明当前token无效
                    return $iatTime <= $cacheValue['valid_until'];
                }
            }
        }

        return false;
    }

    /**
     * 把token加入到黑名单中
     *
     * @param Plain $token
     * @return bool
     */
    public function addTokenBlack(Plain $token): bool
    {
        $sceneConfig = $this->getSceneConfigByToken( $token );
        $claims      = $token->claims();
        if ($sceneConfig['blacklist_enabled']) {
            $cacheKey = $this->getCacheKey( $sceneConfig,$claims->get( RegisteredClaims::ID ) );
            if ($sceneConfig['login_type'] == JWTConstant::MPOP) {
                $blacklistGracePeriod = $sceneConfig['blacklist_grace_period'];
                $iatTime              = TimeUtil::getCarbonTimeByTokenTime( $claims->get( RegisteredClaims::ISSUED_AT ) );
                $validUntil           = $iatTime->addSeconds( $blacklistGracePeriod )->getTimestamp();
            } else {
                /**
                 * 为什么要取当前的时间戳？
                 * 是为了在单点登录下，让这个时间前当前用户生成的token都失效，可以把这个用户在多个端都踢下线
                 */
                $validUntil = TimeUtil::now()->subSeconds( 1 )->getTimestamp();
            }

            /**
             * 缓存时间取当前时间跟jwt过期时间的差值，单位秒
             */
            $tokenCacheTime = $this->getTokenCacheTime( $claims );
            if ($tokenCacheTime > 0) {
                return $this->cache->tag('think-jwt')->set(
                    $cacheKey,
                    ['valid_until' => $validUntil],
                    $tokenCacheTime
                );
            }
        }
        return false;
    }

    /**
     * 获取token缓存时间，根据token的过期时间跟当前时间的差值来做缓存时间
     *
     * @param DataSet $claims
     * @return int
     */
    private function getTokenCacheTime(DataSet $claims): int
    {
        $expTime = TimeUtil::getCarbonTimeByTokenTime( $claims->get( RegisteredClaims::EXPIRATION_TIME ) );
        $nowTime = TimeUtil::now();
        // 优化，如果当前时间大于过期时间，则证明这个jwt token已经失效了，没有必要缓存了
        // 如果当前时间小于等于过期时间，则缓存时间为两个的差值
        if ($nowTime->lte( $expTime )) {
            // 加1秒防止临界时间缓存问题
            return $expTime->diffInSeconds( $nowTime ) + 1;
        }

        return 0;
    }

    /**
     * 刷新token
     *
     * @return Token
     */
    public function refreshToken(string $token = null): Plain
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        $token = $this->tokenToPlain( $token );

        // TODO ....这里是否要做失败处理
        $this->addTokenBlack( $token );

        $claims = $token->claims();
        $data   = JWTUtil::claimsToArray( $claims );
        $scene  = $this->getSceneByClaims( $claims );
        unset( $data[RegisteredClaims::ISSUER] );
        unset( $data[RegisteredClaims::EXPIRATION_TIME] );
        unset( $data[RegisteredClaims::NOT_BEFORE] );
        unset( $data[RegisteredClaims::ISSUED_AT] );
        unset( $data[RegisteredClaims::ID] );
        return $this->getToken( $scene,$data );
    }

    /**
     * 让token失效
     *
     * @param string|null $token
     * @return bool
     */
    public function logout(string $token = null): bool
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        $token = $this->tokenToPlain( $token );
        return $this->addTokenBlack( $token );
    }

    /**
     * 黑名单移除token
     * @param string $token
     * @return int|bool
     */
    public function remove(string $token)
    {
        $token       = $this->tokenToPlain( $token );
        $sceneConfig = $this->getSceneConfigByToken( $token );
        $claims      = $token->claims();
        $cacheKey    = $this->getCacheKey( $sceneConfig,$claims->get( RegisteredClaims::ID ) );
        return $this->cache->delete( $cacheKey );
    }

    /**
     * 移除所有的token缓存
     * @return int|bool
     */
    public function clear()
    {
        return $this->cache->tag('think-jwt')->clear();
    }

    /**
     * 获取token动态有效时间
     *
     * @param string|null $token
     * @return int|mixed
     */
    public function getTokenDynamicCacheTime(string $token = null): int
    {
        if ($token == null) {
            throw new JWTException( "Missing token" );
        }

        $nowTime = TimeUtil::now();
        $expTime = $this->tokenToPlain( $token )->claims()->get( RegisteredClaims::EXPIRATION_TIME,$nowTime );

        $expTime = TimeUtil::getCarbonTimeByTokenTime( $expTime );
        return $nowTime->max( $expTime )->diffInSeconds();
    }

    /**
     * 获取jwt的claims数据
     *
     * @param string $token
     * @return array
     */
    public function getClaimsByToken(string $token = null): array
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        return $this->tokenToPlain( $token )->claims()->all();
    }

    public function tokenToPlain(string $token): Plain
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        try {
            return JWTUtil::getParser()->parse( $token );
        } catch ( JWTException $e ) {
            throw new JWTException( 'Jwt token interpretation error. Please provide the correct jwt token and parse the error information: '.$e->getMessage(),400 );
        }
    }

    public function setScene(string $scene = 'default'): JWT
    {
        $this->scene = $scene;
        return $this;
    }

    public function getScene(): string
    {
        return $this->scene;
    }

    public function getCacheKey(array $sceneConfig,string $claimJti): string
    {
        return $sceneConfig["cache_prefix"].':'.$claimJti;
    }

    /**
     * 获取缓存时间
     *
     * @return int
     */
    public function getCacheTTL(string $token = null): int
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        $token       = $this->tokenToPlain( $token );
        $claimJti    = $token->claims()->get( RegisteredClaims::ID );
        $sceneConfig = $this->getSceneConfigByToken( $token );
        $cacheKey    = $this->getCacheKey( $sceneConfig,$claimJti );
        $cacheValue  = $this->cache->get( $cacheKey );
        return $cacheValue['valid_until'] - time();
    }

    public function getTTL(string $token): int
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }

        $token       = JWTUtil::getParser()->parse( $token );
        $sceneConfig = $this->getSceneConfigByToken( $token );
        return (int)$sceneConfig['ttl'];
    }

    public function getSceneByToken(string $token): bool
    {
        if ($token == null) {
            $token = JWTUtil::getToken( $this->request );
        }
        $token = $this->tokenToPlain( $token );
        $scene = $this->getSceneByTokenPlain( $token );
        return $this->jwtConfig[$scene];
    }

    /**
     * 获取登录用户对象
     */
    public function getUser()
    {
        $token          = JWTUtil::getToken( $this->request );
        $token          = $this->tokenToPlain( $token );
        $jwtSceneConfig = $this->getJwtSceneConfig();
        if (is_callable( $jwtSceneConfig['user_model'] )) {
            return $jwtSceneConfig['user_model']( $token->claims()->get( $jwtSceneConfig['sso_key'] ) ) ?? [];
        }
        throw new JWTException( 'jwt.user_model required',400 );
    }


    /**
     * 获取Signer
     *
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        $jwtSceneConfig = $this->getJwtSceneConfig();
        $alg            = $jwtSceneConfig['alg'];
        if (!array_key_exists( $alg,$this->supportAlgs )) {
            throw new JWTException( 'The given supportAlgs could not be found',400 );
        }

        return new $this->supportAlgs[$alg];
    }

    protected function buildConfig()
    {
        $jwtSceneConfig = $this->getJwtSceneConfig();
        if (!$this->isAsymmetric()) {
            $this->lcobucciJwtConfiguration = Configuration::forSymmetricSigner(
                $this->getSigner(),
                InMemory::base64Encoded( base64_encode( $jwtSceneConfig['secret'] ) )
            );
        } else {
            $this->lcobucciJwtConfiguration = Configuration::forAsymmetricSigner(
                $this->getSigner(),
                InMemory::file( $jwtSceneConfig['keys']['private'],$jwtSceneConfig['keys']['passphrase'] ),
                InMemory::file( $jwtSceneConfig['keys']['public'] )
            );
        }
    }

    /**
     * 判断是否为非对称算法
     */
    protected function isAsymmetric(): bool
    {
        return is_subclass_of( $this->getSigner(),Signer\Rsa::class )
            || is_subclass_of( $this->getSigner(),Signer\Ecdsa::class );
    }

    /**
     * https://lcobucci-jwt.readthedocs.io/en/latest/validating-tokens/
     * JWT 验证时，支持的校验
     * 'Lcobucci\JWT\Validation\Constraint\IdentifiedBy',
     * 'Lcobucci\JWT\Validation\Constraint\IssuedBy',
     * 'Lcobucci\JWT\Validation\Constraint\PermittedFor',
     * 'Lcobucci\JWT\Validation\Constraint\RelatedTo',
     * 'Lcobucci\JWT\Validation\Constraint\SignedWith',
     * 'Lcobucci\JWT\Validation\Constraint\StrictValidAt',
     * 'Lcobucci\JWT\Validation\Constraint\LooseValidAt'
     * @return array
     */
    protected function validationConstraints(DataSet $claims,Configuration $configuration)
    {
        $clock                 = SystemClock::fromUTC();
        $validationConstraints = [
            new IdentifiedBy( $claims->get( RegisteredClaims::ID ) ),
            new IssuedBy( $claims->get( RegisteredClaims::ISSUER ) ),
            new LooseValidAt( $clock ),
            new StrictValidAt( $clock ),
            new SignedWith( $configuration->signer(),$configuration->verificationKey() )
        ];
        if ($claims->get( RegisteredClaims::AUDIENCE ) != null) {
            $validationConstraints[] = new PermittedFor( ...$claims->get( RegisteredClaims::AUDIENCE ) );
        }
        if ($claims->get( RegisteredClaims::SUBJECT ) != null) {
            $validationConstraints[] = new RelatedTo( $claims->get( RegisteredClaims::SUBJECT ) );
        }
        return $validationConstraints;
    }

    /**
     * 通过token获取当前场景的配置
     *
     * @param Plain $token
     * @return string
     */
    protected function getSceneConfigByToken(Plain $token): array
    {
        $scene = $this->getSceneByTokenPlain( $token );
        return $this->jwtConfig[$scene];
    }

    protected function getSceneByClaims(DataSet $claims)
    {
        return $claims->get( $this->jwtClaimScene,$this->getScene() );
    }

    /**
     * @param Plain $token
     * @return string
     */
    protected function getSceneByTokenPlain(Plain $token): string
    {
        $claims = $token->claims()->all();
        return $claims[$this->jwtClaimScene];
    }
}