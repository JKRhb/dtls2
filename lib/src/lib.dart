// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:ffi';
import 'dart:io';

import 'generated/ffi.dart';

export 'generated/ffi.dart';

NativeLibrary loadLibSsl() {
  if (Platform.isIOS) {
    return NativeLibrary(DynamicLibrary.process());
  }
  String? libName;

  if (Platform.isWindows) {
    libName = 'libssl-1_1-x64.dll';
  }

  libName ??= 'libssl.so';

  return NativeLibrary(DynamicLibrary.open(libName));
}

NativeLibrary loadLibCrypto() {
  if (Platform.isIOS) {
    return NativeLibrary(DynamicLibrary.process());
  }
  String? libName;

  if (Platform.isWindows) {
    libName = 'libcrypto-1_1-x64.dll';
  }

  libName ??= 'libcrypto.so';

  return NativeLibrary(DynamicLibrary.open(libName));
}

final libSsl = loadLibSsl();

final libCrypto = loadLibCrypto();

extension DurationTimeval on timeval {
  Duration get duration =>
      Duration(seconds: tv_sec) + Duration(microseconds: tv_usec);
}
