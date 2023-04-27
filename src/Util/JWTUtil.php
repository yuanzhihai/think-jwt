<?php
declare( strict_types = 1 );

namespace yzh52521\Jwt\Util;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Validation\Validator;
use think\Request;

class JWTUtil
{
    const header = 'authorization';

    const prefix = 'Bearer';

    protected static function fromAltHeaders(Request $request)
    {
        return $request->header( 'HTTP_AUTHORIZATION' ) ?: $request->header( 'REDIRECT_HTTP_AUTHORIZATION' );
    }

    /**
     * claims对象转换成数组
     *
     * @param $claims
     * @return mixed
     */
    public static function claimsToArray(DataSet $claims)
    {
        return $claims->all();
    }

    /**
     * 获取jwt token
     * @param Request $request
     * @return array
     */
    public static function getToken(Request $request)
    {
        $authorization = $request->header( self::header ) ?: self::fromAltHeaders($request);
        $token         = self::handleToken( $authorization );
        return $token;
    }

    /**
     * 解析token
     * @param Request $request
     * @return array
     */
    public static function getParserData(Request $request)
    {
        $authorization = $request->header( self::header ) ?: self::fromAltHeaders($request);
        $token         = self::handleToken( $authorization );
        return self::getParser()->parse( $token )->claims()->all();
    }

    /**
     * 处理token
     * @param string $token
     * @param string $prefix
     * @return bool|mixed|string
     */
    public static function handleToken(string $token)
    {
        if (strlen( $token ) > 0) {
            $token  = ucfirst( $token );
            $header = explode( self::prefix." ",$token );
            $token  = $header[1] ?? '';
            if (strlen( $token ) > 0) {
                return $token;
            }
        }
        return false;
    }

    /**
     * @return Parser
     */
    public static function getParser(Decoder $decoder = null): Parser
    {
        if ($decoder == null) {
            return new Parser( new JoseEncoder() );
        }
        return new Parser( $decoder );
    }

    public static function getValidator(): Validator
    {
        return new Validator();
    }
}