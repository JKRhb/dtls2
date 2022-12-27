// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'package:test/test.dart';

import 'package:dtls2/dtls2.dart';

void main() {
  test('create and free context and connection', () {
    final context = DtlsClientContext();
    final connection = DtlsClientConnection(context: context);
    connection.free();
    context.free();
  });
}
