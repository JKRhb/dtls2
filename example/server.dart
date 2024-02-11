// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

// ignore_for_file: avoid_print

import "dart:convert";

import "package:dtls2/dtls2.dart";

const _identity = "Client_identity";

const _preSharedKey = "secretPSK";

final _serverKeyStore = {_identity: _preSharedKey};

const _ciphers = "PSK-AES128-CCM8";

Iterable<int>? _serverPskCallback(List<int> identity) {
  final identityString = utf8.decode(identity);

  final psk = _serverKeyStore[identityString];

  if (psk == null) {
    return null;
  }

  return utf8.encode(psk);
}

void main() async {
  const bindAddress = "::";
  const peerPort = 5684;

  final dtlsServer = await DtlsServer.bind(
    bindAddress,
    peerPort,
    DtlsServerContext(
      pskKeyStoreCallback: _serverPskCallback,
      ciphers: _ciphers,
      identityHint: "This is the identity hint!",
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
}
