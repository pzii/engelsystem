<?php

declare(strict_types=1);

namespace Engelsystem\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\Pivot;
use Illuminate\Database\Query\Builder as QueryBuilder;

/**
 * @mixin Builder
 *
 * @property int       $id
 * @property int       $user_id
 * @property int       $location_id
 *
 * @method static QueryBuilder|UserLocation[] whereId($value)
 * @method static QueryBuilder|UserLocation[] whereUserId($value)
 * @method static QueryBuilder|UserLocation[] whereLocationId($value)
  */
class UserLocation extends Pivot
{
    use HasFactory;

    /** @var bool Increment the IDs */
    public $incrementing = true; // phpcs:ignore

    /** @var bool Disable timestamps */
    public $timestamps = false; // phpcs:ignore

    /** @var array<string, null|bool> default attributes */
    protected $attributes = [ // phpcs:ignore
    ];

    protected $table = 'users_locations_access'; // phpcs:ignore

    /**
     * Returns a list of attributes that can be requested for this pivot table
     *
     * @return string[]
     */
    public static function getPivotAttributes(): array
    {
        return ['id'];
    }
}
