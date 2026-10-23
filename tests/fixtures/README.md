These certificates and private keys are **public test fixtures only**. Never use
them on a real server. They are valid for ten years from generation in 2026.

Both server certificates use P-384 keys, DNS SAN `localhost`, serverAuth EKU,
and ECDSA-with-SHA-512 signatures. One is issued by a P-384 CA, the other by a
P-521 CA. Tests trust the corresponding CA explicitly and also check rejection
of untrusted issuers and mismatched hostnames.

To regenerate each chain with OpenSSL, use `genpkey -algorithm EC -pkeyopt
ec_paramgen_curve:secp384r1` (or `secp521r1` for the second CA), create a CA
certificate with `req -new -x509 -sha512 -days 3650` and critical CA/keyCertSign
constraints, then issue a P-384 server CSR with `x509 -req -sha512 -days 3650`.
The server extensions are:

```ini
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
```
