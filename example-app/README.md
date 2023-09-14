# Example WebAuthn application

To run this locally, you may want to use
[`mkcert`](https://github.com/FiloSottile/mkcert) to generate a certificate.
Note that `mkcert` needs a rootCA installed, which is done with
`mkcert -install`.

I ran the following to create my certificate, adjust the IP address and your
`.local` address accordingly.

```bash
mkcert "localhost" "127.0.0.1" "::1" "192.168.1.140" "levis-macbook-pro.local"
```

It will create a file like `localhost+4-key.pem` and `localhost+4.pem`. I named
these `localhost-key.pem` and `localhost-cert.pem` respectively.

Then, if you want to get your certificate onto another machine for testing, copy
the root CA certificate somewhere like so

```bash
cp "$(mkcert -CAROOT)"/rootCA.pem static/
```

Finally, edit `https.json` and fill the `rpId` field with your chosen hostname,
then set the origin's host name as well.

If you plan to adjust the `secret` field, it must be 256 bits of randomness
encoded as base64url.

## Obvious disclaimer

The example app is for educational and demonstration purposes, it is not
intended to be used in production for anything meaningful.

## Testing on windows

The above commands are meant for a linux / macOS / maybe freeBSD environment.
The section is about how to test a local webauthn service hosted elsewhere with
`mkcert` on a windows machine for Windows Hello.

While the screenshots look like they are from 1998, the instructions are still
relevant. Review
[How to import intermediate and root certificates via MMC](https://www.ssls.com/knowledgebase/how-to-import-intermediate-and-root-certificates-via-mmc/)

For some reason, my `.local` address was not accessible on my windows machine. I
fixed that by using Notepad as administrator to edit
`System32/drivers/etc/hosts` where I added the line

```
192.168.1.140 levis-macbook-pro.local
```
