// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'package:test/test.dart';

import 'package:dtls/dtls.dart';

void main() {
  test('create and free context and connection', () {
    final context = DtlsClientContext();
    final connection = DtlsClientConnection(context: context);
    connection.free();
    context.free();
  });
}
