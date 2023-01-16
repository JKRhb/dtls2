## 0.10.0

- chore!: bump required Dart version to 2.17
- refactor: refactor alert handling using enhanced enums

## 0.9.0

- feat: replace `TlsException`s with `DtlsException`
- feat: add DTLS server implementation
- docs: update README

## 0.8.2

- docs: fix documentation of `DtlsException`

## 0.8.1

- fix(client): improve connection closing behavior
- refactor: refactor DTLS client

## 0.8.0

- feat!: pass `DtlsClientContext` to `connect` method
- feat: add `timeout` parameter to `connect` method

## 0.7.0

- feat!: use `DynamicLibrary` objects for loading libssl and libcrpyto externally
- feat!: don't expose `OpenSsl` ffi class

## 0.6.0

- chore: update dependencies, upgrade to ffi 2.x.x

## 0.5.2

- fix: fix hostname verification of X.509 certificates

## 0.5.1

- feat: shutdown DTLS connection upon closing

## 0.5.0

- refactor: rename `NativeLibrary` class to `OpenSsl`
- feat: expose `OpenSsl` class

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
