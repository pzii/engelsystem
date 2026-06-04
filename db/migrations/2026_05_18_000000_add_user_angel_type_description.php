<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddUserAngelTypeDescription extends Migration
{
    /**
     * Run the migration
     */
    public function up(): void
    {
        $this->schema->table('user_angel_type', function (Blueprint $table): void {
            $table->text('description')->default('')->after('supporter');
        });
    }

    /**
     * Reverse the migration
     */
    public function down(): void
    {
        $this->schema->table('user_angel_type', function (Blueprint $table): void {
            $table->dropColumn('description');
        });
    }
}
