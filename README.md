# dtls

DTLS provides datagram socket encryption. Implemented using OpenSSL over FFI.
This package supports native platforms only, because there are no datagram sockets on Web.

## Features

Currently, only the client side is implemented.

## Getting started

libssl (OpenSSL) needs to be available.

- On Android and iOS, libssl has to be bundled with the app.
- On Linux, libssl is preinstalled or available in most distributions.

## Usage

First, create a DtlsClientContext.
Then, create a DtlsClientConnection for each encrypted connection.
