// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:ffi';
import 'dart:io';

import 'generated/ffi.dart';

export 'generated/ffi.dart';

final lib = NativeLibrary(Platform.isIOS
    ? DynamicLibrary.process()
    : DynamicLibrary.open('libssl.so'));

extension DurationTimeval on timeval {
  Duration get duration =>
      Duration(seconds: tv_sec) + Duration(microseconds: tv_usec);
}
