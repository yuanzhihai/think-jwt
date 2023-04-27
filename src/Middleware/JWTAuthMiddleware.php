<?php

namespace yzh52521\Jwt\Middleware;

use think\Request;
use yzh52521\Jwt\Exception\TokenValidException;
use yzh52521\Jwt\JWT;
use yzh52521\Jwt\Util\JWTUtil;

class JWTAuthMiddleware
{

    public function __construct(protected JWT $jwt)
    {
    }

    public function process(Request $request,callable $next)
    {
        $token = JWTUtil::getToken( $request );
        if ($token !== false && $this->jwt->verifyToken( $token )) {
            return $next( $request );
        }

        throw new TokenValidException( 'Token authentication does not pass',400 );
    }
}