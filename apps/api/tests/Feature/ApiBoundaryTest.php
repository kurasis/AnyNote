<?php

namespace Tests\Feature;

use App\Contracts\Catalogue;
use App\Generated\P03ApiLiveness;
use App\Http\ApiErrors;
use App\Http\ApiException;
use App\Http\ControlJson;
use App\Logging\ContentFreeFormatter;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Monolog\Level;
use Monolog\LogRecord;
use Tests\TestCase;

final class ApiBoundaryTest extends TestCase
{
    public function test_capabilities_and_request_id_do_not_claim_product_auth_or_trust_hostile_headers(): void
    {
        $origin = config('api.app_origin');
        $one = $this->withHeaders(['X-Request-ID' => 'hostile-synthetic-id', 'Origin' => $origin])->get('http://api.anynote.test/api/v1/capabilities')->assertOk();
        $one->assertJsonPath('features.production_ready', false)->assertJsonPath('negotiation.components.3', 'p02-group-c2');
        $this->assertNotSame('hostile-synthetic-id', $one->headers->get('X-Request-ID'));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{21}[AQgw]$/D', $one->headers->get('X-Request-ID'));
        $one->assertHeader('Access-Control-Allow-Origin', $origin)->assertHeader('Access-Control-Allow-Credentials', 'true');
        $two = $this->get('http://api.anynote.test/api/v1/capabilities');
        $this->assertNotSame($one->headers->get('X-Request-ID'), $two->headers->get('X-Request-ID'));
        $this->assertSame(['status' => 'live'], (new P03ApiLiveness('live'))->jsonSerialize());
    }

    public function test_profile_cors_and_preflight_reject_downgrades_and_hostile_origins(): void
    {
        $origin = config('api.app_origin');
        $this->withHeaders(['X-AnyNote-Profile' => 'p02-group-c1'])->get('http://api.anynote.test/api/v1/capabilities')->assertStatus(400)->assertJsonPath('error.code', 'UNSUPPORTED_SCHEMA');
        $this->withHeaders(['X-AnyNote-Profile' => 'p02-v1', 'Origin' => 'https://hostile.anynote.test'])->get('http://api.anynote.test/api/v1/capabilities')->assertNotFound()->assertHeaderMissing('Access-Control-Allow-Origin');
        $this->withHeaders(['Origin' => $origin, 'Access-Control-Request-Method' => 'POST', 'Access-Control-Request-Headers' => 'content-type,x-anynote-profile,x-csrf-token'])->options('http://api.anynote.test/api/v1/auth/passkeys/verify')->assertNoContent();
        $this->withHeaders(['Origin' => $origin, 'Access-Control-Request-Headers' => 'x-exfiltrate'])->options('http://api.anynote.test/api/v1/auth/passkeys/verify')->assertNotFound();
    }

    public function test_missing_and_unauthorized_resources_have_identical_safe_errors(): void
    {
        Route::get('/api/v1/synthetic-denied', fn () => throw new AuthorizationException('synthetic title /private/path SELECT password'));
        $a = $this->get('http://api.anynote.test/api/v1/synthetic-missing')->assertNotFound()->json('error');
        $b = $this->get('http://api.anynote.test/api/v1/synthetic-denied')->assertNotFound()->json('error');
        unset($a['request_id'], $b['request_id']);
        $this->assertSame($a, $b);
        $this->assertSame([], $a['details']);
    }

    public function test_exception_debug_and_validation_details_never_escape_the_boundary(): void
    {
        config(['app.debug' => true]);
        Route::get('/api/v1/synthetic-error', fn () => throw new \RuntimeException('synthetic body token PRF private key SELECT password /private/path'));
        $r = $this->get('http://api.anynote.test/api/v1/synthetic-error')->assertStatus(503)->assertJsonPath('error.code', 'TEMPORARY_UNAVAILABLE')->assertHeader('Retry-After', '1');
        $this->assertStringNotContainsString('synthetic body', $r->getContent());
        $this->assertStringNotContainsString('trace', $r->getContent());
        $this->assertLessThanOrEqual(4096, strlen($r->getContent()));
    }

    public function test_every_transport_error_has_exact_mapping_and_bounded_trusted_details(): void
    {
        foreach (Catalogue::data()['errors']['errors'] as $e) {
            if ($e['local_only']) {
                continue;
            }
            $r = ApiErrors::response(Request::create('/api/v1/test'), $e['code'], [['key' => 'retry_after_ms', 'value' => '60001'], ['key' => 'sql', 'value' => 'synthetic secret']]);
            $v = $r->getData(true)['error'];
            $this->assertSame($e['http_status'], $r->getStatusCode());
            $this->assertSame($e['message_key'], $v['message_key']);
            $this->assertSame($e['retryable'], $v['retryable']);
            $this->assertSame([], $v['details']);
        }
        $r = ApiErrors::response(Request::create('/'), 'RATE_LIMITED', [['key' => 'retry_after_ms', 'value' => '60000']]);
        $this->assertSame('60', $r->headers->get('Retry-After'));
        $this->expectException(\LogicException::class);
        ApiErrors::response(Request::create('/'), 'EXPORT_TRUNCATED');
    }

    public function test_raw_control_json_preserves_duplicates_utf8_depth_and_observed_length(): void
    {
        $this->assertSame('quoted \\ " value', ControlJson::decode('{"body":"quoted \\\\ \\" value","array":[{"x":1},{"x":2}]}')->body);
        $this->assertInstanceOf(\stdClass::class, ControlJson::decode(str_repeat('{"a":', 31).'{}'.str_repeat('}', 31)));
        foreach (['{"a":1e9999}', '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"nested":{"a":1,"a":2}}', "{\"bad\":\"\xff\"}", '['.str_repeat('[', 33).'0'.str_repeat(']', 33).']', '{"body":"'.str_repeat('x', 4194304).'"}', '{"a":"\\ud800"}', '{"a":1,}', '[]'] as $raw) {
            try {
                ControlJson::decode($raw);
                $this->fail('Unsafe JSON accepted');
            } catch (ApiException $e) {
                $this->assertContains($e->errorCode, ['INVALID_REQUEST', 'REQUEST_TOO_LARGE']);
            }
        }
    }

    public function test_logger_discards_arbitrary_messages_exceptions_headers_body_sql_and_extra(): void
    {
        $format = new ContentFreeFormatter;
        $record = new LogRecord(new \DateTimeImmutable, 'raw-channel', Level::Error, 'synthetic token /private/path SELECT secret', ['exception' => new \RuntimeException('synthetic private key'), 'body' => 'synthetic note title', 'headers' => ['Authorization' => 'synthetic token'], 'status' => 503, 'method' => 'GET', 'route_id' => '/private/path', 'code' => 'SQL_SECRET'], ['password' => 'synthetic secret']);
        $result = $format->format($record);
        $this->assertSame(['event' => 'application.event', 'status' => 503, 'method' => 'GET'], json_decode($result, true));
        $this->assertLessThan(512, strlen($result));
    }

    public function test_product_routes_and_service_identity_are_fail_closed_in_production(): void
    {
        $this->app['env'] = 'production';
        $this->withHeaders(['X-Forwarded-Proto' => 'https'])->get('http://api.anynote.test/api/v1/capabilities')->assertStatus(400);
        config(['api.service_id' => null, 'api.app_origin' => null]);
        $this->get('https://api.anynote.test/api/v1/capabilities')->assertStatus(503);
        // P09 owns private groups; missing production configuration denies them.
        $this->get('https://api.anynote.test/api/v1/groups')->assertStatus(503)->assertJsonPath('error.code', 'TEMPORARY_UNAVAILABLE');
        $this->get('https://api.anynote.test/api/v1/groups/AAAAAAAAAAAAAAAAAAAAAA/members')->assertNotFound();
        // P06 owns this route now; malformed unauthenticated mutation fails Laravel CSRF.
        $this->postJson('https://api.anynote.test/api/v1/auth/passkeys/verify', ['credential' => 'synthetic'])->assertStatus(400);
        $this->get('https://api.anynote.test/api/v1/health/live')->assertOk()->assertExactJson(['status' => 'live']);
    }
}
