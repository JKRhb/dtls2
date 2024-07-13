[![pub package](https://img.shields.io/pub/v/dtls2.svg)](https://pub.dev/packages/dtls2)
[![Build](https://github.com/JKRhb/dtls2/actions/workflows/ci.yml/badge.svg)](https://github.com/JKRhb/dtls2/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/JKRhb/dtls2/branch/main/graph/badge.svg?token=76OBNOVL60)](https://codecov.io/gh/JKRhb/dtls2)
[![style: lint](https://img.shields.io/badge/style-lint-4BC0F5.svg)](https://pub.dev/packages/lint)

# dtls2

DTLS provides datagram socket encryption. Implemented using OpenSSL over FFI.
This package supports native platforms only, because there are no datagram sockets on Web.
It is based on the [`dtls`](https://pub.dev/packages/dtls) package which was
discontinued by its maintainers but offers a more convenient API as well as
additional features.

## Features

The library provides both a client and a server implementation with support
for DTLS in PKI and PSK mode.
While only OpenSSL 3 is actively supported and tested with, the library might
also still be compatible with OpenSSL 1.1.1, although this is not guaranteed.

## Limitations

Connecting to a server currently does not seem to work on macOS.

Futhermore, during the DTLS handshake, messages currently get corrupted when too
many cipher suites are offered to the server, making it impossible to complete
the handshake.
The issue will probably be fixed with the release of OpenSSL 3.2.

To circumvent the problem, you can specify a specific set of ciphers in the
`DTLSClientContext` (see the example in the `examples` directory, where only the
 cipher `PSK-AES128-CCM8` is selected).
This will reduce the size of the Client Hello, preventing it from being fragmented.
See the [OpenSSL documentation](https://www.openssl.org/docs/man3.0/man1/ciphers.html)
for a full list of available cipher strings.

Note that you might need to also lower the security level for the underlying
OpenSSL library (via the `securityLevel` parameter in the DTLS context classes)
to be able to use deprecated ciphers such as `PSK-AES128-CCM8` that might still
be required to communicate with IoT devices.

test

## Getting started

The dynamic libraries libssl and libcrypto from OpenSSL need to be available.

On Android and iOS, libssl and libcrypto have to be bundled with the app.
On macOS and Windows, libssl and libcrypto might also not be available
by default and might need to be bundled.
However, you can install them on macOS via homebrew (`brew install openssl`)
and on Windows, e.g., via package managers such as chocolatey
(`choco install openssl`).

On Linux, libssl and libcrypto are preinstalled or available in most distributions.

## Usage

In order to connect to a DTLS server, first create a `DtlsClientContext`.
The context can be configured to use a certain set of ciphers and/or a callback
function for Pre-Shared Keys.

With the context, you can then create a `DtlsClient` by either using the
`bind()` method or its constructor (which requires an external
`RawDatagramSocket`).

With the `DtlsClient`, you can then `connect` to peers, which will return a
`DtlsConnection` on success.
The connection object allows you to `send` data to the peer or to `listen` for
incoming data.
Incoming data is wrapped in `Datagram` objects, which makes it easier to
integrate the library in contexts where `RawDatagramSocket`s are already being
used.

In similar way, you can create a `DtlsServer` based on a `DtlsServerContext`.
Servers implement the `Stream` interface, which means that you can `listen`
for incoming connections.
Once a connection has been established, you can use the same API as the one
offered by the client side, calling `send` and `listen`.

Once the data exchange is finished, you can either close the connection or the
client.
The latter will also close all active connections associated with the closed
client.

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dtls2/dtls2.dart';

const _identity = "Client_identity";

const _preSharedKey = "secretPSK";

final _serverKeyStore = {_identity: _preSharedKey};

Uint8List? _serverPskCallback(Uint8List identity) {
  final identityString = utf8.decode(identity.toList());

  final psk = _serverKeyStore[identityString];

  if (psk == null) {
    return null;
  }

  return Uint8List.fromList(utf8.encode(psk));
}

final context = DtlsClientContext(
  verify: true,
  withTrustedRoots: true,
  pskCredentialsCallback: (identityHint) {
    return PskCredentials(
      identity: Uint8List.fromList(utf8.encode(_identity)),
      preSharedKey: Uint8List.fromList(utf8.encode(_preSharedKey)),
    );
  },
);

void main() async {
  const bindAddress = "::";
  final peerAddress = InternetAddress("::1");
  final peerPort = 5684;

  final dtlsServer = await DtlsServer.bind(
      bindAddress,
      peerPort,
      DtlsServerContext(
        pskKeyStoreCallback: _serverPskCallback,
      ));

  dtlsServer.listen(
    (connection) {
      connection.listen(
        (event) async {
          print(utf8.decode(event.data));
          connection.send(Uint8List.fromList(utf8.encode('Bye World')));
        },
      );
    },
  );

  final dtlsClient = await DtlsClient.bind(bindAddress, 0);

  final DtlsConnection connection;
  try {
    connection = await dtlsClient.connect(
      peerAddress,
      peerPort,
      context,
      timeout: Duration(seconds: 5),
    );
  } on TimeoutException {
    await dtlsClient.close();
    rethrow;
  }

  connection
    ..listen(
      (datagram) async {
        print(utf8.decode(datagram.data));
        await dtlsClient.close();
        await dtlsServer.close();
      },
    )
    ..send(Uint8List.fromList(utf8.encode('Hello World')));
}
```
