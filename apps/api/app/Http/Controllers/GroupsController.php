<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Policy;
use App\Auth\RateLimits;
use App\Auth\Sessions;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol;
use App\Groups\Service;
use App\Http\ApiException;
use Illuminate\Http\Request;

final class GroupsController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private RateLimits $limits, private Service $service) {}

    public function __invoke(Request $r)
    {
        Policy::check();
        if ($r->headers->has('Authorization') ? ($r->headers->has('Origin') || $r->headers->has('Cookie')) : $r->header('Origin') !== config('api.app_origin')) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $session = $this->sessions->current($r);
        $this->limits->hit('p10-session', $session->id, 120);
        $this->limits->hit('p10-ip', $r->ip(), 180);
        $id = $r->route('id');
        Protocol::require($id === null || P::isBinary($id, 16), 'NOT_FOUND');
        $op = $r->route()->getName();
        if ($op === 'post_me_close_account') {
            Protocol::require($r->getQueryString() === null && $r->attributes->get('anynote_control') instanceof \stdClass, 'INVALID_REQUEST');
            $body = $this->contracts->value('p10', 'account-close-request', $r->attributes->get('anynote_control'));
            $result = $this->service->closeAccount($r, $body);
            $this->contracts->value('p10', 'account-close-result', json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

            return response()->json($result);
        }
        if ($r->isMethod('GET')) {
            Protocol::require($r->getContent() === '', 'INVALID_REQUEST');
            $q = DevicesController::query($r, $op === 'get_me_group_invitations' ? ['after'] : ($op === 'get_me_group_receipts_id' ? ['family'] : []));
            if ($op === 'get_me_group_receipts_id') {
                Protocol::require(isset($q['family']) && in_array($q['family'], ['invite', 'accept', 'policy', 'consent', 'begin', 'commit', 'history', 'cancel'], true), 'INVALID_REQUEST');
                $result = $this->service->readReceipt($r, $id, $q['family']);
                $this->contracts->value('p10', 'result', json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

                return response()->json($result);
            }
            Protocol::require(! isset($q['after']) || P::isBinary($q['after'], 16), 'INVALID_REQUEST');
            $result = $op === 'get_me_group_invitations' ? $this->service->invitations($r, $q['after'] ?? null) : $this->service->read($r, $id);
            $shape = $op === 'get_me_group_invitations' ? 'invitations-page' : 'journal';
        } else {
            Protocol::require($r->getQueryString() === null && $r->attributes->get('anynote_control') instanceof \stdClass, 'INVALID_REQUEST');
            $family = match ($op) {
                'post_groups_id_invites' => 'invite','post_groups_id_accept' => 'accept','post_groups_id_policy' => 'policy','post_groups_id_owner_consent' => 'consent','post_groups_id_epoch_begin' => 'begin','post_groups_id_epoch_page' => 'page','post_groups_id_epoch_commit' => 'commit','post_groups_id_history' => 'history','post_groups_id_cancel' => 'cancel',default => throw new ApiException('NOT_FOUND')
            };
            $shape = match ($family) {
                'invite' => 'invitation-request','consent' => 'policy-request',default => $family.'-request'
            };
            $body = $this->contracts->value('p10', $shape, $r->attributes->get('anynote_control'));
            $result = $this->service->mutate($r, $id, $family, $body);
            $shape = 'result';
        }
        Protocol::require(strlen(json_encode($result, JSON_THROW_ON_ERROR)) <= 4194304, 'RESOURCE_LIMIT');
        $this->contracts->value('p10', $shape, json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

        return response()->json($result);
    }
}
