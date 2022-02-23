// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'package:dtls2/dtls2.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

final ctx = DtlsClientContext(
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
  final peerAddr = (await InternetAddress.lookup(hostname)).first;
  final peerPort = 5684;

  final sock = await RawDatagramSocket.bind('::', 0);
  final dtls = DtlsClientConnection(context: ctx, hostname: hostname);
  sock.listen((ev) async {
    if (ev == RawSocketEvent.read) {
      final d = sock.receive();
      if (d != null) {
        dtls.incoming(d.data);
      }
    }
  });
  dtls.outgoing.listen((d) => sock.send(d, peerAddr, peerPort));

  // dtls.received should be processed by the appliction.
  // In this example, simply print the plaintext.
  dtls.received.listen((m) => print('> ${utf8.decode(m)}'),
      onDone: () => print('connection closed'));

  // The connection needs to be established before data can be sent.
  await dtls.connect();

  dtls.send(Uint8List.fromList(utf8.encode('Hello World')));
}
