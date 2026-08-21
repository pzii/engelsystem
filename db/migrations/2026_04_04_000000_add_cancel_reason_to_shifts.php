<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddCancelReasonToShifts extends Migration
{
    /**
     * Run the migration
     */
    public function up(): void
    {
        if (!$this->schema->hasColumn('shifts', 'cancel_reason')) {
            $this->schema->table('shifts', function (Blueprint $table): void {
                $table->string('cancel_reason')->nullable()->after('description');
            });
        }
    }

    /**
     * Reverse the migration
     */
    public function down(): void
    {
        $this->schema->table('shifts', function (Blueprint $table): void {
            $table->dropColumn('cancel_reason');
        });
    }
}
