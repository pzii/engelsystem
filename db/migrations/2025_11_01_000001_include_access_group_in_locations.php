<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class IncludeAccessGroupInLocations extends Migration
{
    /**
     * Run the migration
     */
    public function up(): void
    {
        $this->schema->table('locations', function (Blueprint $table): void {
            $table->string('access_group')->nullable()->default(null)->after('description');
        });
    }

    /**
     * Reverse the migration
     */
    public function down(): void
    {
        $this->schema->table('locations', function (Blueprint $table): void {
            $table->dropColumn('access_group');
        });
    }
}
