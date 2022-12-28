# dtls2

DTLS provides datagram socket encryption. Implemented using OpenSSL over FFI.
This package supports native platforms only, because there are no datagram sockets on Web.
It is based on the [`dtls`](https://pub.dev/packages/dtls) package which was
discontinued by its maintainers.

## Features

Currently, only the client side is implemented.

## Getting started

libssl (OpenSSL) needs to be available.

- On Android and iOS, libssl has to be bundled with the app.
- On Linux, libssl is preinstalled or available in most distributions.
- On Windows, libssl 1.1.1 (`libssl-1_1-x64.dll`) needs to be installed or bundled with the application

## Usage

First, create a DtlsClientContext.
Then, create a DtlsClientConnection for each encrypted connection.
