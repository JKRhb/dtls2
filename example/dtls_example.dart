// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'package:dtls/dtls.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

final ctx = DtlsClientContext(
  verify: true,
  withTrustedRoots: true,
  ciphers: 'aRSA',
);

void main() async {
  final hostname = 'example.com';
  final peerAddr = (await InternetAddress.lookup(hostname)).first;
  final peerPort = 4444;

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
