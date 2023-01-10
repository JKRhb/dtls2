// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'package:dtls2/dtls2.dart';
import 'package:test/test.dart';

void main() {
  test('create and free context and connection', () async {
    final dtlsClient = await DtlsClient.bind("::", 0);
    await dtlsClient.close();
  });
}
