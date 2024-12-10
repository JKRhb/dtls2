## 0.17.0

### New Features

- Added standalone server example
- Made send APIs asynchronous (breaking change)
- Introduced new requiresClosing state

## Fixes

- Use new requiresClosing state for alert handling
- Prevent clients t from crashing when using empty PSK
- Let server actually perform shutdown on connection loss
- Let client throw SocketException if not connected anymore

## [0.18.0](https://github.com/JKRhb/dtls2/compare/v0.17.0...v0.18.0) (2024-12-10)


### ⚠ BREAKING CHANGES

* update dependencies
* increase minimal Dart SDK version to 3.0.0

### Features

* add security level parameter to DTLS contexts ([25ed88f](https://github.com/JKRhb/dtls2/commit/25ed88ffe8720e5e35517b6b7f25e0bdad962477))
* generate binding for SSL_CTX_set_security_level ([445c6e6](https://github.com/JKRhb/dtls2/commit/445c6e6d9115e05d066d2159917f93f8cc9d9a17))
* regenerate bindings ([7075590](https://github.com/JKRhb/dtls2/commit/7075590c089150081116cca3f0088b9850bfe7e0))


### Bug Fixes

* lower security level for main example ([274edfa](https://github.com/JKRhb/dtls2/commit/274edfac42b432d87bf34018e32ea01314f38e87))


### Miscellaneous Chores

* fix release please configuration ([317b92f](https://github.com/JKRhb/dtls2/commit/317b92f13a5031d0765839085b25da95e55c4d9b))
* increase minimal Dart SDK version to 3.0.0 ([a4e421b](https://github.com/JKRhb/dtls2/commit/a4e421b50575d8f8e1780ff4db63dda5cc25e3fa))
* update dependencies ([9894b2b](https://github.com/JKRhb/dtls2/commit/9894b2bb654f450451ac4fa1f378d30fe3b3cdf3))

## 0.16.0

### New Features

- Added support for M1 Macs using OpenSSL installed via Homebrew
- Introduced a new `DtlsTimeoutException`

### Fixes

- Fixed a bug that could cause a segmentation fault for the server when a client closed the connection
- Fixed a bug that caused failed client-side handshakes to emit uncatchable Exceptions

## 0.15.0

- fix: properly handle unreachable network
- fix: avoid segmentation fault for client connection
- feat: add additional library names for OpenSSL 3 discovery

## 0.14.1

- fix(client): throw SocketException if Network is unreachable

## 0.14.0

- fix(server): fix server behavior during handshake
- feat: expose state of connections
- chore: use lint package for stricter linting
- fix(dtls_client): improve error handling

## 0.13.4

- fix: shutdown connections only when actually connected
- fix: fix client behavior during connection closing
- fix: fix server behavior during connection closing

## 0.13.3

- ci: simplify code coverage generation
- refactor: refactor connection closing mechanism
- refactor: refactor client connection setup
- test: increase test coverage
- refactor: refactor DTLS server implementation
- fix: don't close client or server connection twice during alert handling

## 0.13.2

- fix(client): handle unreachable network

## 0.13.1

- docs: add library documentation

## 0.13.0

- feat!: rework library loading

## 0.12.1

- fix: use correct name for libcrypto load exception
- fix(dtls_client): switch loading order of libcrypto and libssl

## 0.12.0

- feat!: simplify identity hint determination
- feat!: do not use typed_data types for external APIs

## 0.11.0

- fix(dtls_client): throw exception if no ciphers are available
- fix: close client and server when the underlying socket is closed
- fix: export `DtlsException` class

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
