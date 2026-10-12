"""Synthetic TPM-format impostor signed by a SOFTWARE RSA key, never hardware proof.

Default verifies the committed public-only fixture with the independently pinned
Python cryptography dependency. --generate makes fresh ephemeral software keys,
writes only public components/signature/nonce, and retains no private key.
TPM structure definitions: microsoft/TSS.MSR 52cb9f4 TSS.Py/src/TpmTypes.py.
PCP wrapper: microsoft/win32metadata 1bfb76d ncrypt.h. Synthetic assembly only,
not an observed NCryptCreateClaim result or an authenticated hardware claim.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

FILE = Path(__file__).with_name('tpm-certification.json')


def sized(value):
    return struct.pack('>H', len(value)) + value


def cng_public(key):
    numbers = key.public_key().public_numbers()
    modulus = numbers.n.to_bytes(256, 'big')
    return struct.pack('<6I', 0x31415352, 2048, 3, 256, 0, 0) + b'\x01\x00\x01' + modulus


def pcp_wrapper(info, signature, public):
    return struct.pack('<6I', 0x4B415741, 1, 24, len(info), len(signature), len(public)) + info + signature + public


def generate():
    subject = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aik = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    modulus = subject.public_key().public_numbers().n.to_bytes(256, 'big')
    # TPMT_PUBLIC: RSA/SHA256, fixedTPM/Parent/origin/userWithAuth/decrypt,
    # empty policy, NULL symmetric/scheme, RSA2048/default exponent, modulus.
    public = struct.pack('>HHI', 1, 11, 0x20072) + sized(b'')
    public += struct.pack('>HHHI', 16, 16, 2048, 0) + sized(modulus)
    name = b'\x00\x0b' + hashlib.sha256(public).digest()
    nonce = bytes(range(32))
    # Synthetically declared qualified names; these have NO trusted TPM origin.
    signer = b'\x00\x0b' + hashlib.sha256(cng_public(aik)).digest()
    info = struct.pack('>IH', 0xFF544347, 0x8017) + sized(signer) + sized(nonce)
    info += struct.pack('>QIIBQ', 123456, 1, 2, 1, 3)
    info += sized(name) + sized(name)
    signature = aik.sign(info, padding.PKCS1v15(), hashes.SHA256())
    fixture = {
        'provenance': 'Synthetic software-signed TPM-format impostor. No TPM, certificate or Passport claim.',
        'signatureAlgorithm': 'rsassa-pkcs1-sha256',
        'nonce': nonce,
        'cngSubject': cng_public(subject),
        'cngAik': cng_public(aik),
        'cngOtherAik': cng_public(other),
        'publicArea': public,
        'certifyInfo': info,
        'signature': signature,
        'expectedSubjectName': name,
        'pcpWebAuthnClaim': pcp_wrapper(info, signature, public),
    }
    encoded = {k: base64.b64encode(v).decode('ascii') if isinstance(v, bytes) else v
               for k, v in fixture.items()}
    FILE.write_text(json.dumps(encoded, indent=2) + '\n')


def verify():
    fixture = json.loads(FILE.read_text())
    value = lambda key: base64.b64decode(fixture[key], validate=True)
    blob = value('cngAik')
    assert struct.unpack('<6I', blob[:24]) == (0x31415352, 2048, 3, 256, 0, 0)
    key = rsa.RSAPublicNumbers(int.from_bytes(blob[24:27], 'big'),
                              int.from_bytes(blob[27:], 'big')).public_key()
    key.verify(value('signature'), value('certifyInfo'), padding.PKCS1v15(), hashes.SHA256())
    assert value('expectedSubjectName') == b'\x00\x0b' + hashlib.sha256(value('publicArea')).digest()
    assert value('nonce') == bytes(range(32))
    assert value('publicArea')[22:] == value('cngSubject')[27:]
    assert value('certifyInfo')[44:76] == value('nonce')
    assert value('certifyInfo')[103:137] == value('expectedSubjectName')
    claim = value('pcpWebAuthnClaim')
    assert claim == pcp_wrapper(value('certifyInfo'), value('signature'), value('publicArea'))
    assert struct.unpack('<6I', claim[:24]) == (0x4B415741, 1, 24, 173, 256, 278)
    assert len(claim) == 731
    # Independently verify the signed bytes extracted from the committed wrapper.
    key.verify(claim[197:453], claim[24:197], padding.PKCS1v15(), hashes.SHA256())
    assert claim[453:] == value('publicArea')
    print('PASS: independent Python RSA signature, PCP frame, exact subject/Name/nonce; synthetic software signer has NO TPM trust.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    if args.generate:
        generate()
    verify()
