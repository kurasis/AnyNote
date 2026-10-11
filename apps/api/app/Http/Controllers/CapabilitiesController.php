<?php

namespace App\Http\Controllers;

use App\Auth\Policy;
use App\Contracts\Catalogue;
use App\Http\ApiException;
use Illuminate\Http\JsonResponse;

final class CapabilitiesController
{
    public function __invoke(): JsonResponse
    {
        $service = config('api.service_id');
        if (! is_string($service) || ! preg_match('/^[A-Za-z0-9_-]{21}[AQgw]$/D', $service)) {
            throw new ApiException('TEMPORARY_UNAVAILABLE');
        }

        return response()->json([
            'service_id' => $service,
            'negotiation' => ['contract' => 'p02-v1', 'protocol' => 'anynote', 'protocol_version' => 1, 'purpose' => 'protocol-negotiation', 'profile' => 'p02-v1', 'api_version' => 1, 'wire_version' => 1, 'payload_version' => 1, 'local_schema' => 1, 'export_version' => 1, 'minimum_reader' => 1, 'minimum_writer' => 1, 'components' => Catalogue::data()['components']],
            'limits' => ['control_bytes' => '4194304', 'page_bytes' => '1048576', 'file_plaintext_bytes' => '1000000000', 'global_ciphertext_bytes' => '100000000000', 'group_members' => 20],
            'features' => ['account_authentication' => Policy::configured(), 'device_activation' => false, 'content_storage' => false, 'sync' => false, 'file_transfer' => false, 'production_ready' => false],
        ]);
    }
}
