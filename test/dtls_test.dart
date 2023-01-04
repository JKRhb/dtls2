// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'package:dtls2/dtls2.dart';
import 'package:test/test.dart';

void main() {
  test('create and free context and connection', () async {
    final context = DtlsClientContext();
    final dtlsClient = await DtlsClient.bind("::", 0, context);
    dtlsClient.close();
  });
}
