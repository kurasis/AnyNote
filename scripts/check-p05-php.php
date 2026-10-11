<?php
// PUBLIC signature-only corpus: this process receives no root/group/local keys or payloads.
declare(strict_types=1);
require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
use App\Crypto\PublicProtocol;
use App\Http\ApiException;
use App\Http\ControlJson;
$input=json_decode(file_get_contents($argv[1]),false,32,JSON_THROW_ON_ERROR);
if ($input->purpose !== 'PUBLIC_SIGNATURE_ONLY_P05') throw new RuntimeException('INVALID_TEST_PURPOSE');
$p=new PublicProtocol; $checks=0;
function must(bool $v):void{global $checks;if(!$v)throw new RuntimeException('PUBLIC_SIGNATURE_MISMATCH');$checks++;}
function denied(callable $f):void{try{$f();}catch(ApiException){must(true);return;}throw new RuntimeException('INVALID_SIGNATURE_ACCEPTED');}
foreach ($input->sources as $source) {
 foreach ($source->frames as $f) {
  $raw=hex2bin($f->raw_hex);
  $body=$p->signedFrame($f->profile,$f->kind,$raw,$f->signature,$f->public_key);
  must(bin2hex(PublicProtocol::canonical($body))===$f->canonical_hex);
  must(str_ends_with(hex2bin($f->signing_hex),PublicProtocol::canonical($body)));
  $sig=PublicProtocol::binary($f->signature);$sig[0]=chr(ord($sig[0])^1);
  denied(fn()=>$p->signedFrame($f->profile,$f->kind,$raw,PublicProtocol::b64($sig),$f->public_key));
  denied(fn()=>$p->signedFrame($f->profile,$f->kind,$raw,$f->signature,PublicProtocol::b64(str_repeat(chr(254),32))));
  $bad=json_decode($raw,false,32,JSON_THROW_ON_ERROR);$bad->unexpected_p05_field=true;
  denied(fn()=>$p->signedFrame($f->profile,$f->kind,json_encode($bad,JSON_THROW_ON_ERROR),$f->signature,$f->public_key));
 }
}
foreach($input->malformed as $hex)denied(fn()=>ControlJson::decode(hex2bin($hex)));
// Encrypted payload/local data must never become a server plaintext decoder.
foreach(['payload','local-plaintext','vault-secrets'] as $kind)denied(fn()=>$p->decode('p02-v1',$kind,'{}'));
echo json_encode(['status'=>'PASS','scope'=>'PUBLIC_SIGNATURE_ONLY_P05','php'=>PHP_VERSION,'checks'=>$checks,'sources'=>array_map(fn($s)=>['runtime'=>$s->runtime,'frames'=>count($s->frames)],$input->sources),'physical_acceptance'=>false],JSON_THROW_ON_ERROR)."\n";
