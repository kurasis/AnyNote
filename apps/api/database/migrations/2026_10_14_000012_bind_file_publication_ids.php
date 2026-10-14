<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('file_publication_ids', function (Blueprint $t) {
            foreach (['account_id', 'device_id', 'operation_id', 'upload_id'] as $name) {
                $t->char($name, 22)->collation('ascii_bin');
            }
            $t->primary(['account_id', 'device_id', 'operation_id']);
            $t->unique('upload_id');
        });
        foreach (DB::table('upload_sessions')->whereNotNull('context_record')->get() as $u) {
            DB::table('file_publication_ids')->insert(['account_id' => $u->account_id, 'device_id' => $u->device_id, 'operation_id' => json_decode($u->context_record)->operation_id, 'upload_id' => $u->id]);
        }
        Schema::table('gc_coordination', function (Blueprint $t) {
            $t->char('last_blob_scan', 22)->collation('ascii_bin')->nullable();
        });
    }

    public function down(): void
    {
        throw new LogicException('Explicit immutable publication-ID migration required');
    }
};
