# Optional private Windows HTTPS setup for physical trials

Status: procedure prepared; certificate provisioning, firewall access and
physical phone trust **NOT RUN** in this cloud task. Prefer an existing trusted
private origin if available. This is development test infrastructure, not a
production certificate or deployment.

Use Node 24.21.0, the repository's frozen npm install and a private Windows
LAN address reachable by the iPhone on the same controlled network. The
certificate must cover that actual address/name. Allow only the test port from
the phone on the private network using your normal firewall policy; do not
disable the firewall or expose the unauthenticated server to the Internet.

If no development certificate exists, mkcert is an optional established local
CA tool. Official release observed: [v1.4.4](https://github.com/FiloSottile/mkcert/releases/tag/v1.4.4);
the [upstream mobile instructions](https://github.com/FiloSottile/mkcert#mobile-devices)
require installing the CA certificate and explicitly enabling iOS trust. It
is not installed or executed by this repository. Obtain the tool through the
official distribution or an already trusted package manager; retain its source
and integrity receipt. The release API supplies no asset digest, so this task
does not invent a verified binary hash.

The following commands are a manual procedure after that tool is available.
Use a dedicated certificate directory outside the checkout. Replace the private
address with the actual PC address; keep it stable for the trial:

```powershell
New-Item -ItemType Directory -Path C:\P01-TLS
mkcert -cert-file C:\P01-TLS\test-cert.pem -key-file C:\P01-TLS\test-key.pem YOUR_PRIVATE_LAN_IP
mkcert -CAROOT
```

Only transfer the **public** `rootCA.pem` from the reported CA directory to your
own iPhone, using a private route. Never transfer `rootCA-key.pem` or the server
private key. On iPhone, install the downloaded certificate profile in Settings,
then explicitly enable its trust under General > About > Certificate Trust
Settings, per [Apple's instructions](https://support.apple.com/102390).
This changes the phone's trusted roots: keep the CA key private and remove the
test certificate profile after the trials. Installing roots is an owner action,
not a hidden TLS exception or automatic cloud operation. `mkcert -install` on
Windows is unnecessary for a server-only setup; desktop test clients also need
normal explicit trust if used.

Start the server using the command in [the owner runbook](P01_OWNER_TRIALS.md),
with the same actual private address and certificate paths. Safari must open
the configured HTTPS origin without a certificate error before installing the
PWA. If trust, reachability or an enforced policy prevents that, record BLOCKED;
do not proceed through an untrusted-certificate warning.

Stop only the test server with Ctrl+C after each trial. Its orderly shutdown
removes its own temporary ciphertext. Explicitly clean marked PWA exports,
then remove the test profile when no longer needed. No personal vault, Hello
settings, production origin, or server-side plaintext is involved.
