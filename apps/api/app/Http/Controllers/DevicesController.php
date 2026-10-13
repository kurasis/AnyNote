<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Policy;
use App\Auth\RateLimits;
use App\Auth\Sessions;
use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Devices\Envelopes;
use App\Devices\Lifecycle;
use App\Devices\Protocol;
use App\Devices\Settings;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class DevicesController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private RateLimits $limits) {}

    public function __invoke(Request $r)
    {
        Policy::check();
        if ($r->headers->has('Authorization') ? ($r->headers->has('Origin') || $r->headers->has('Cookie')) : $r->header('Origin') !== config('api.app_origin')) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $op = $r->route()->getName();
        $id = $r->route('id');
        if ($id !== null && ! P::isBinary($id, 16)) {
            throw new ApiException('NOT_FOUND');
        }
        $this->limits->hit('p08-ip-'.$op, $r->ip(), $r->isMethod('GET') ? 120 : 60);
        $s = $this->sessions->current($r);
        $this->limits->hit('p08-session-'.$op, $s->id, $r->isMethod('GET') ? 60 : 20);
        $kinds = ['post_me_enrollments' => 'create-request', 'post_me_enrollments_id_relay' => 'relay-request', 'post_me_enrollments_id_approve' => 'approve-request', 'post_me_enrollments_id_confirm' => 'event-request', 'post_me_devices_id_revoke' => 'event-request', 'post_me_recovery_challenge' => 'challenge-request', 'post_me_recovery_reset' => 'event-request', 'delete_me_enrollments_id' => 'empty-request', 'post_me_settings_genesis' => 'genesis-request', 'post_me_device_envelopes' => 'envelope-request'];
        $body = null;
        if (isset($kinds[$op])) {
            if ($r->getQueryString() !== null || strlen($r->getContent()) > 262144) {
                throw new ApiException('INVALID_REQUEST');
            }
            Protocol::require($r->attributes->get('anynote_control') instanceof \stdClass, 'INVALID_REQUEST');
            $body = $this->contracts->value('p08', $kinds[$op], $r->attributes->get('anynote_control'));
        } elseif ($r->getContent() !== '' || ($r->getQueryString() !== null && ! in_array($op, ['get_accounts_id_roster', 'get_me_device_envelopes', 'get_me_recovery_envelopes'], true))) {
            throw new ApiException('INVALID_REQUEST');
        }
        [$result, $shape] = match ($op) {
            'get_accounts_id_identity' => [$this->identity($r, $id), 'identity-result'],
            'get_accounts_id_roster' => [$this->roster($r, $id), 'roster-result'],
            'get_me_devices' => [$this->devices($r), 'devices-result'],
            'get_me_security_notifications' => [$this->notifications($r), 'notifications-result'],
            'post_me_enrollments' => [app(Lifecycle::class)->create($r, $body), 'pending-result'],
            'get_me_enrollments_id_relay' => [app(Lifecycle::class)->relay($r, $id, null), 'relay-result'],
            'post_me_enrollments_id_relay' => [app(Lifecycle::class)->relay($r, $id, $body), 'relay-result'],
            'post_me_enrollments_id_approve' => [app(Lifecycle::class)->approve($r, $id, $body), 'pending-result'],
            'post_me_enrollments_id_confirm' => [app(Lifecycle::class)->confirm($r, $id, $body), 'event-result'],
            'post_me_devices_id_revoke' => [app(Lifecycle::class)->revoke($r, $id, $body), 'event-result'],
            'post_me_recovery_challenge' => [app(Lifecycle::class)->challenge($r, $body), 'challenge-result'],
            'post_me_recovery_reset' => [app(Lifecycle::class)->reset($r, $body), 'event-result'],
            'delete_me_enrollments_id' => [app(Lifecycle::class)->cancel($r, $id), 'cancel-result'],
            'post_me_settings_genesis' => [app(Settings::class)->create($r, $body), 'genesis-result'],
            'get_me_settings_genesis' => [app(Settings::class)->read($r), 'genesis-result'],
            'post_me_device_envelopes' => [app(Envelopes::class)->publish($r, $body), 'cancel-result'],
            'get_me_device_envelopes' => [app(Envelopes::class)->read($r, false), 'envelope-result'],
            'get_me_recovery_envelopes' => [app(Envelopes::class)->read($r, true), 'envelope-result'],
            default => throw new ApiException('NOT_FOUND'),
        };
        if (strlen(json_encode($result, JSON_THROW_ON_ERROR)) > 262144) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        $this->contracts->value('p08', $shape, json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

        return response()->json($result);
    }

    public static function query(Request $r, array $allowed): array
    {
        $q = [];
        foreach ($r->server->get('QUERY_STRING', '') === '' ? [] : explode('&', $r->server->get('QUERY_STRING')) as $part) {
            $p = explode('=', $part, 2);
            Protocol::require(count($p) === 2 && ! preg_match('/%(?![0-9A-Fa-f]{2})/', $part), 'INVALID_REQUEST');
            $key = urldecode($p[0]);
            Protocol::require(in_array($key, $allowed, true) && ! isset($q[$key]), 'INVALID_REQUEST');
            $q[$key] = urldecode($p[1]);
        }

        return $q;
    }

    private function identity(Request $r, string $id): array
    {
        $this->sessions->current($r);
        $i = DB::table('account_identities')->join('users', 'users.id', '=', 'account_identities.account_id')->where('account_id', $id)->where('users.status', 'active')->first();
        Protocol::require($i !== null, 'NOT_FOUND');

        return ['version' => 1, 'identity' => json_decode($i->identity_record)];
    }

    private function roster(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $s = $this->sessions->current($r, true);
            $q = self::query($r, ['after', 'head', 'root']);
            Protocol::require(! isset($q['root']) || P::isBinary($q['root'], 32), 'INVALID_REQUEST');
            if ($s->account_id !== $id) {
                app(Authorization::class)->actor($this->sessions->secret($r));
                $target = DB::table('account_identities')->where('account_id', $id)->first();
                Protocol::require((isset($q['root']) && $target && $q['root'] === $target->root_fingerprint) || DB::table('group_memberships as a')->join('group_memberships as b', 'a.group_id', '=', 'b.group_id')->where('a.account_id', $s->account_id)->where('b.account_id', $id)->where('a.status', 'active')->where('b.status', 'active')->exists(), 'NOT_FOUND');
            }
            $i = DB::table('account_identities')->where('account_id', $id)->first();
            Protocol::require($i !== null, 'NOT_FOUND');
            Protocol::require(! isset($q['after']) || P::counter($q['after'], '1000'), 'INVALID_REQUEST');
            $head = Protocol::head($i);
            if (isset($q['head'])) {
                Protocol::require(P::isBinary($q['head'], 32), 'INVALID_REQUEST');
                $h = DB::table('account_roster_events')->where('account_id', $id)->where('digest', $q['head'])->first();
                Protocol::require($h !== null, 'ROSTER_CHANGED');
                $head = (object) ['version' => (string) $h->sequence, 'digest' => $h->digest];
            }
            $from = $q['after'] ?? '0';
            Protocol::require((int) $from <= (int) $head->version + 1, 'INVALID_REQUEST');
            $rows = DB::table('account_roster_events')->where('account_id', $id)->where('sequence', '>=', $from)->where('sequence', '<=', $head->version)->orderBy('sequence')->limit(20)->get();
            $events = [];
            $bytes = 0;
            foreach ($rows as $row) {
                if ($bytes + strlen($row->signed_record) > 196608 && $events !== []) {
                    break;
                } $bytes += strlen($row->signed_record);
                $events[] = json_decode($row->signed_record);
            }
            $next = (int) $from + count($events);
            $last = DB::table('account_roster_events')->where('account_id', $id)->where('digest', $head->digest)->first();

            return ['version' => 1, 'identity' => json_decode($i->identity_record), 'head' => $head, 'generation' => json_decode($last->signed_record)->body->generation, 'events' => $events, 'next' => $next <= (int) $head->version ? (string) $next : null];
        }, 3);
    }

    private function devices(Request $r): array
    {
        return DB::transaction(function () use ($r) {
            $s = $this->sessions->current($r, true);
            app(Authorization::class)->actor($this->sessions->secret($r));
            $rows = DB::table('devices')->where('account_id', $s->account_id)->orderBy('id')->limit(1001)->get();
            Protocol::require($rows->count() <= 1000, 'RESOURCE_LIMIT');

            return ['version' => 1, 'devices' => $rows->map(fn ($d) => ['device_id' => $d->id, 'status' => $d->status, 'generation' => (string) $d->recovery_generation, 'certificate' => json_decode($d->certificate_record), 'current' => $d->id === $s->device_id, 'platform' => $d->platform, 'enrolled_at' => $d->enrolled_at, 'last_contact' => DB::table('auth_sessions')->where('device_id', $d->id)->max('last_seen_at')])->all()];
        }, 3);
    }

    private function notifications(Request $r): array
    {
        $s = $this->sessions->current($r);

        return ['version' => 1, 'notifications' => DB::table('account_security_notifications')->where('account_id', $s->account_id)->orderByDesc('created_at')->orderBy('id')->limit(100)->get()->map(fn ($n) => ['id' => $n->id, 'kind' => $n->kind, 'created_at' => $n->created_at])->all()];
    }
}
