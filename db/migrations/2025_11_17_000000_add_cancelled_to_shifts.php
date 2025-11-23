<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddCancelledToShifts extends Migration
{
    /**
     * Run the migration
     */
    public function up(): void
    {
        $this->schema->table('shifts', function (Blueprint $table): void {
            $table->boolean('cancelled')->default(false)->after('description');
        });
    }

    /**
     * Reverse the migration
     */
    public function down(): void
    {
        $this->schema->table('shifts', function (Blueprint $table): void {
            $table->dropColumn('cancelled');
        });
    }
}
