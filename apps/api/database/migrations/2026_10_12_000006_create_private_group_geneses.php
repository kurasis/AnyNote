<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('private_group_geneses', function (Blueprint $t) {
            $t->string('group_id', 22)->collation('ascii_bin')->primary();
            $t->string('account_id', 22)->collation('ascii_bin');
            $t->string('device_id', 22)->collation('ascii_bin');
            $t->string('operation_id', 22)->collation('ascii_bin');
            $t->string('request_digest', 43)->collation('ascii_bin');
            $t->mediumText('commit_record');
            $t->mediumText('grant_page');
            $t->unique(['account_id', 'device_id', 'operation_id']);
            $t->foreign('group_id')->references('id')->on('groups');
            $t->foreign('account_id')->references('id')->on('users');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('private_group_geneses');
    }
};
