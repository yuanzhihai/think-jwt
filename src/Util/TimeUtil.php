<?php
declare( strict_types = 1 );

namespace yzh52521\Jwt\Util;

use Carbon\Carbon;

class TimeUtil
{
    /**
     * Get the Carbon instance for the current time.
     *
     * @return \Carbon\Carbon
     */
    public static function now()
    {
        return Carbon::now( date_default_timezone_get() );
    }

    /**
     * Get the Carbon instance for the timestamp.
     *
     * @param int $timestamp
     *
     * @return \Carbon\Carbon
     */
    public static function timestamp($timestamp)
    {
        return Carbon::createFromTimestamp($timestamp, date_default_timezone_get());
    }

    /**
     * Checks if a timestamp is in the past.
     *
     * @param int $timestamp
     * @param int $leeway
     *
     * @return bool
     */
    public static function isPast($timestamp,$leeway = 0)
    {
        return static::timestamp( $timestamp )->addSeconds( $leeway )->isPast();
    }

    /**
     * Checks if a timestamp is in the future.
     *
     * @param int $timestamp
     * @param int $leeway
     *
     * @return bool
     */
    public static function isFuture($timestamp,$leeway = 0)
    {
        return static::timestamp( $timestamp )->subSeconds( $leeway )->isFuture();
    }

    /**
     * 获取carbon实例
     *
     * @param $time
     * @return Carbon
     */
    public static function getCarbonTimeByTokenTime($tokenTime): Carbon
    {
        $timestamp = $tokenTime;
        if (!is_numeric( $tokenTime )) {
            $timestamp = $tokenTime->getTimestamp();
        }

        return self::timestamp( $timestamp );
    }
}