## 0.4.0

- feat: look for multiple default OpenSSL file names
- feat: allow passing custom libSsl and libCrypto objects
- feat: add additional default macOS lib paths
- chore: also run CI on Windows and macOS
- fix: fix macOS homebrew paths
- chore: adjust example
- docs: update README
- fix: don't iterate over connection cache for incoming data

## 0.3.0

- feat!: improve memory safety of DtlsClientContext
- fix: fix caching of DTLS connections in clients
- fix!: make connection closing asynchronous

## 0.2.2

- chore: rename example file

## 0.2.1

- fix: call BIO_free on the correct NativeLibrary object

## 0.2.0

- feat: define callback for handling DTLS alerts
- feat!: refactor library, rework external API

## 0.1.0

- initial version with added PSK functionality and Windows support
