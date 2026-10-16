<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('operations_restore_state', function (Blueprint $table) {
            $table->unsignedTinyInteger('singleton')->primary();
            $table->boolean('quarantined')->default(false);
        });
        DB::table('operations_restore_state')->insert(['singleton' => 1, 'quarantined' => false]);
    }

    public function down(): void
    {
        throw new LogicException('A restored service fence cannot be removed by migration rollback');
    }
};
