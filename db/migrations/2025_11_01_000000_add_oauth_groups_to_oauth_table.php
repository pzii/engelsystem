<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddOauthGroupsToOauthTable extends Migration
{
    /**
     * Run the migration
     */
    public function up(): void
    {
        $this->schema->table('oauth', function (Blueprint $table): void {
            $table->json('oauth_groups')->nullable()->after('refresh_token');
        });
    }

    /**
     * Reverse the migration
     */
    public function down(): void
    {
        $this->schema->table('oauth', function (Blueprint $table): void {
            $table->dropColumn('oauth_groups');
        });
    }
}
