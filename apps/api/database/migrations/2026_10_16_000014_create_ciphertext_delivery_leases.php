<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ciphertext_delivery_leases', function (Blueprint $table) {
            $table->char('id', 22)->collation('ascii_bin')->primary();
            $table->timestamp('expires_at')->index();
        });
    }

    public function down(): void
    {
        throw new LogicException('Drain ciphertext delivery leases before an explicit operator rollback');
    }
};
