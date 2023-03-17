// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dtls2/dtls2.dart';
import 'package:dtls2/src/dtls_alert.dart';
import 'package:test/test.dart';

const ciphers = "PSK-AES128-CCM8";

const identity = "Client_identity";

const preSharedKey = "secretPSK";

final serverKeyStore = {identity: preSharedKey};

final bindAddress = InternetAddress.anyIPv4;

Iterable<int>? _serverPskCallback(Iterable<int> identity) {
  final identityString = utf8.decode(identity.toList());

  final psk = serverKeyStore[identityString];

  if (psk == null) {
    return null;
  }

  return utf8.encode(psk);
}

final clientContext = DtlsClientContext(
  verify: true,
  withTrustedRoots: true,
  ciphers: ciphers,
  pskCredentialsCallback: (identityHint) {
    return PskCredentials(
      identity: Uint8List.fromList(utf8.encode(identity)),
      preSharedKey: Uint8List.fromList(utf8.encode(preSharedKey)),
    );
  },
);

final serverContext = DtlsServerContext(
  pskKeyStoreCallback: _serverPskCallback,
  ciphers: ciphers,
);

void main() {
  test('create and free context and connection', () async {
    final dtlsClient = await DtlsClient.bind(bindAddress, 0);
    await dtlsClient.close();
  });

  test(
    'Client and server test',
    () async {
      final completer = Completer<void>();
      const address = "127.0.0.1";
      const port = 9001;

      final dtlsClient = await DtlsClient.bind(bindAddress, 0);
      final dtlsServer =
          await DtlsServer.bind(bindAddress, port, serverContext);

      final clientPayload = "Hello World";
      final serverPayload = "Bye World";

      dtlsServer.listen(
        (connection) {
          connection.listen(
            (event) async {
              expect(utf8.decode(event.data), clientPayload);
              connection.send(Uint8List.fromList(utf8.encode(serverPayload)));
            },
          );
        },
      );

      final connection = await dtlsClient.connect(
        InternetAddress(address),
        port,
        clientContext,
      );

      final secondConnection = await dtlsClient.connect(
        InternetAddress(address),
        port,
        clientContext,
      );

      expect(connection == secondConnection, isTrue);

      expect(connection.connected, isTrue);

      connection
        ..listen(
          (datagram) async {
            expect(utf8.decode(datagram.data), serverPayload);
            completer.complete();
          },
        )
        ..send(Uint8List.fromList(utf8.encode(clientPayload)));

      await completer.future;
      await dtlsServer.close();
      await dtlsClient.close();

      expect(connection.connected, isFalse);
    },
    onPlatform: <String, dynamic>{
      "mac-os": [
        Skip("on macOS, SSL_connct somehow fails. This needs to be fixed."),
      ]
    },
  );

  test('Parse DTLS alerts', () {
    final code = 1 << 8;

    final alert = DtlsAlert.fromCode(code);
    expect(alert?.alertLevel, AlertLevel.warning);
    expect(alert?.alertDescription, AlertDescription.closeNotify);
    expect(alert?.requiresClosing, true);
    expect(
      alert?.toString(),
      "DtlsEvent with Alert Level 'Warning' and description 'close_notify'.",
    );
  });
}
