<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class FoundationTest extends TestCase
{
    public function test_readiness_uses_actual_mariadb(): void
    {
        $this->assertStringContainsString('MariaDB', DB::selectOne('SELECT VERSION() AS version')->version);
        $this->getJson('http://api.anynote.test/health/ready')->assertOk()->assertExactJson(['status' => 'ready']);
    }

    public function test_tooling_routes_and_commands_are_unavailable_in_production(): void
    {
        $this->app['env'] = 'production';
        $this->getJson('http://api.anynote.test/health/ready')->assertNotFound();
        $this->assertSame(1, Artisan::call('foundation:check'));
    }

    public function test_temporary_transaction_probe_preserves_existing_tables(): void
    {
        $before = DB::select('SHOW TABLES');
        $this->assertSame(0, Artisan::call('foundation:check'));
        $this->assertSame(json_encode($before), json_encode(DB::select('SHOW TABLES')));
    }
}
