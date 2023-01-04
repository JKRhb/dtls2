// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dtls2/dtls2.dart';

final context = DtlsClientContext(
  verify: true,
  withTrustedRoots: true,
  ciphers: 'PSK-AES128-CCM8',
  pskCredentialsCallback: (identityHint) {
    return PskCredentials(
      identity: Uint8List.fromList(utf8.encode("Client_identity")),
      preSharedKey: Uint8List.fromList(utf8.encode("secretPSK")),
    );
  },
);

void main() async {
  final hostname = 'californium.eclipseprojects.io';
  final peerAddr = InternetAddress.tryParse(hostname) ??
      (await InternetAddress.lookup(hostname)).first;
  final peerPort = 5684;

  final dtlsClient = await DtlsClient.bind('::', 0, context);

  final connection = await dtlsClient.connect(peerAddr, peerPort);

  connection
    ..listen((datagram) {
      print('> ${utf8.decode(datagram.data)}');
      connection.close();
      print('Connection closed');
    }, onDone: () {
      dtlsClient.close();
      print('Client closed');
    })
    ..send(Uint8List.fromList(utf8.encode('Hello World')));
}
