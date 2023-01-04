// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:ffi';
import 'dart:io';

import 'generated/ffi.dart';

export 'generated/ffi.dart';

/// Loads libssl as a [NativeLibrary].
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

/// Loads libcrypto as a [NativeLibrary].
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

/// The global libssl object.
final libSsl = loadLibSsl();

/// The global libcrypto object.
final libCrypto = loadLibCrypto();
