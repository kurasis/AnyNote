<?php

// Mounted only by the owned synthetic drill; excluded from immutable API images.
use App\Crypto\PublicProtocol as P;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
set_exception_handler(function (Throwable $error): void {
    fwrite(STDERR, json_encode(['status' => 'FAIL', 'class' => get_class($error), 'code' => $error->getCode(), 'driver_code' => $error instanceof QueryException ? ($error->errorInfo[1] ?? null) : null, 'source' => basename($error->getFile()), 'line' => $error->getLine()], JSON_THROW_ON_ERROR)."\n");
    exit(1);
});
if (! $app->runningInConsole() || ! hash_equals((string) getenv('ANYNOTE_P16_OWNER'), (string) DB::table('p16_test_owner')->value('owner'))) {
    throw new LogicException('Owned P16 synthetic database required');
}
$input = json_decode(stream_get_contents(STDIN) ?: '{}');
$result = match ($argv[1] ?? '') {
    'invite' => (function () {
        $token = P::b64(random_bytes(32));
        DB::table('account_invites')->insert(['id' => P::b64(random_bytes(16)), 'creator_id' => null, 'bootstrap' => true, 'token_hash' => hash('sha256', $token), 'expires_at' => now()->addHour(), 'status' => 'pending']);

        return ['token' => $token];
    })(),
    'admin-role' => (function () use ($input) {
        DB::table('users')->where('id', $input->account_id)->update(['is_admin' => true]);

        return ['status' => 'PASS'];
    })(),
    'revoke-session' => (function () use ($input) {
        DB::table('auth_sessions')->where('account_id', $input->account_id)->update(['state' => 'revoked']);

        return ['status' => 'PASS'];
    })(),
    'expire' => (function () use ($input) {
        $session = DB::table('auth_sessions')->where('account_id', $input->account_id)->where('state', '!=', 'revoked')->value('id');
        if (! $session) {
            throw new LogicException('Live synthetic creator session required');
        }
        DB::table('enrollment_sessions')->insert(['creator_session_id' => $session, 'new_session_id' => $session, 'mode' => 'new-device-offer', 'public_record' => '{}', 'id' => P::b64(random_bytes(16)), 'account_id' => $input->account_id, 'commitment' => P::b64(random_bytes(32)), 'state' => 'pending', 'expires_at' => now()->subDays(3)]);
        DB::table('account_invites')->where('status', 'pending')->update(['expires_at' => now()->subDays(3)]);
        DB::table('auth_challenges')->update(['expires_at' => now()->subDays(3)]);
        DB::table('enrollment_sessions')->whereIn('state', ['pending', 'approved'])->update(['expires_at' => now()->subDays(3)]);
        DB::table('upload_sessions')->whereIn('state', ['reserved', 'receiving'])->update(['expires_at' => now()->subDays(3)]);

        return ['status' => 'PASS'];
    })(),
    default => throw new LogicException('Unknown fixture action'),
};
echo json_encode($result, JSON_THROW_ON_ERROR)."\n";
