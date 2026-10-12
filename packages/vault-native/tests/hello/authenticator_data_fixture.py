"""Public synthetic WebAuthn wire data; never a passkey, PRF or hardware proof.

W3C WebAuthn Level 3 section 6.1 / 6.5.1:
https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data
Independent big-endian struct encoding and P-256 public-point validation.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric import ec

FILE = Path(__file__).with_name('authenticator-data.json')
RP = 'p01.anynote.desktop.invalid'
# The public NIST P-256 generator point. No private key or signature is used.
X = bytes.fromhex('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')
Y = bytes.fromhex('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
COSE = b'\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20' + X + b'\x22\x58\x20' + Y
PREFIX = struct.Struct('>32sBI16sH')


def generate():
    credential = bytes(range(16))
    digest = hashlib.sha256(RP.encode('utf-8')).digest()
    data = PREFIX.pack(digest, 0x45, 0, bytes(16), len(credential)) + credential + COSE
    fixture = {
        'provenance': 'Public synthetic W3C-layout data with a NIST P-256 generator point; no key creation, signature, PRF or hardware observation.',
        'rpId': RP,
        'authenticatorData': base64.b64encode(data).decode('ascii'),
        'credentialId': base64.b64encode(credential).decode('ascii'),
        'credentialPublicKey': base64.b64encode(COSE).decode('ascii'),
        'assertionData': base64.b64encode(struct.pack('>32sBI', digest, 5, 0)).decode('ascii'),
    }
    FILE.write_text(json.dumps(fixture, indent=2) + '\n', encoding='utf-8')


def verify():
    fixture = json.loads(FILE.read_text(encoding='utf-8'))
    value = lambda name: base64.b64decode(fixture[name], validate=True)
    data, credential = value('authenticatorData'), value('credentialId')
    digest, flags, counter, aaguid, length = PREFIX.unpack_from(data)
    assert PREFIX.size == 55
    assert digest == hashlib.sha256(fixture['rpId'].encode('utf-8')).digest()
    assert flags == 0x45 and counter == 0 and aaguid == bytes(16)
    assert data[53:55] == struct.pack('>H', len(credential))
    assert length == len(credential) == 16 and data[55:55 + length] == credential
    assert data[55 + length:] == value('credentialPublicKey') == COSE
    ec.EllipticCurvePublicNumbers(int.from_bytes(X, 'big'), int.from_bytes(Y, 'big'), ec.SECP256R1()).public_key()
    assert value('assertionData') == struct.pack('>32sBI', digest, 5, 0)
    print('PASS: independent W3C big-endian prefix (55 bytes), credential ID and valid public P-256 COSE fixture; no hardware/PRF proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    if args.generate:
        generate()
    verify()
