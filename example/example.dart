// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

// ignore_for_file: avoid_print

import "dart:async";
import "dart:convert";
import "dart:io";

import "package:dtls2/dtls2.dart";

const _identity = "Client_identity";

const _preSharedKey = "secretPSK";

final _serverKeyStore = {_identity: _preSharedKey};

const _ciphers = "PSK-AES128-CCM8";

// Needed to still be able to use PSK-AES128-CCM8 as a cipher suite with more
// recent versions of OpenSSL.
//
// In production scenarios, you probably want to use a higher security level
// and more secure cipher suites instead.
// For this example, the security level is lowered since `PSK-AES128-CCM8`
// is the mandatory cipher suite for CoAPS (Constrained Application Protocol,
// secured with DTLS).
const securityLevel = 0;

Iterable<int>? _serverPskCallback(List<int> identity) {
  final identityString = utf8.decode(identity);

  final psk = _serverKeyStore[identityString];

  if (psk == null) {
    return null;
  }

  return utf8.encode(psk);
}

final context = DtlsClientContext(
  withTrustedRoots: true,
  ciphers: _ciphers,
  securityLevel: securityLevel,
  pskCredentialsCallback: (identityHint) {
    print(identityHint);
    return PskCredentials(
      identity: utf8.encode(_identity),
      preSharedKey: utf8.encode(_preSharedKey),
    );
  },
);

void main() async {
  const bindAddress = "::";
  final peerAddress = InternetAddress("::1");
  const peerPort = 5684;

  final dtlsServer = await DtlsServer.bind(
    bindAddress,
    peerPort,
    DtlsServerContext(
      pskKeyStoreCallback: _serverPskCallback,
      ciphers: _ciphers,
      identityHint: "This is the identity hint!",
      securityLevel: securityLevel,
    ),
  );

  dtlsServer.listen(
    (connection) {
      connection.listen(
        (event) async {
          print(utf8.decode(event.data));
          await connection.send(utf8.encode("Bye World"));
          await connection.close();
        },
        onDone: () async {
          await dtlsServer.close();
          print("Server connection closed.");
        },
      );
    },
    onDone: () => print("Server closed."),
  );

  final dtlsClient = await DtlsClient.bind(bindAddress, 0);

  final DtlsConnection connection;
  try {
    connection = await dtlsClient.connect(
      peerAddress,
      peerPort,
      context,
      timeout: const Duration(seconds: 5),
    );
  } on TimeoutException {
    await dtlsClient.close();
    rethrow;
  }

  connection.listen(
    (datagram) async {
      print(utf8.decode(datagram.data));
      await connection.close();
      print("Client connection closed.");
    },
    onDone: () async {
      await dtlsClient.close();
      print("Client closed.");
    },
  );
  await connection.send(utf8.encode("Hello World"));
}
