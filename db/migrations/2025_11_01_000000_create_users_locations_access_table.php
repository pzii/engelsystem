<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class CreateUsersLocationsAccessTable extends Migration
{
    use ChangesReferences;
    use Reference;

    /**
     * Creates the new table
     */
    public function up(): void
    {
        $this->schema->create('users_locations_access', function (Blueprint $table): void {
            $table->increments('id');
            $this->references($table, 'users');
            $this->references($table, 'locations');
        });
    }

    /**
     * Drops the table
     */
    public function down(): void
    {
        $this->schema->drop('users_locations_access');
    }
}
