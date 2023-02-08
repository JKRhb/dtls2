// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dtls2/dtls2.dart';

const _identity = "Client_identity";

const _preSharedKey = "secretPSK";

final _serverKeyStore = {_identity: _preSharedKey};

const _ciphers = "PSK-AES128-CCM8";

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
  ciphers: _ciphers,
  pskCredentialsCallback: (identityHint) {
    print(identityHint);
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
        ciphers: _ciphers,
        identityHint: "This is the identity hint!",
      ));

  dtlsServer.listen(
    (connection) {
      connection.listen(
        (event) async {
          print(utf8.decode(event.data));
          connection.send(Uint8List.fromList(utf8.encode('Bye World')));
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
        await connection.close();
        print('Client connection closed.');
      },
      onDone: () async {
        await dtlsClient.close();
        print('Client closed.');
      },
    )
    ..send(Uint8List.fromList(utf8.encode('Hello World')));
}
