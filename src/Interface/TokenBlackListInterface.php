<?php

namespace yzh52521\Jwt\Interface;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Plain;

/**
 * User: yzh52521
 */
interface TokenBlackListInterface
{
    /**
     * token加入黑名单
     *
     * @param Token $token
     * @return bool
     */
    public function addTokenBlack(Plain $token): bool;

    /**
     * 黑名单是否存在当前token
     *
     * @param array $claims
     * @return bool
     */
    public function hasTokenBlack(Plain $token): bool;

    /**
     * @param array $sceneConfig
     * @param string $claimJti
     * @return string
     */
    public function getCacheKey(array $sceneConfig,string $claimJti): string;

    /**
     * Get the cache time limit.
     *
     * @return int
     */
    public function getCacheTTL(string $token = null): int;
}