// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:ffi';
import 'dart:io';

import 'generated/ffi.dart';
import 'openssl_load_exception.dart';

NativeLibrary _loadLibrary(List<String> libNames, String libName) {
  for (final libName in libNames) {
    try {
      return NativeLibrary(DynamicLibrary.open(libName));
      // ignore: avoid_catching_errors
    } on ArgumentError {
      continue;
    }
  }

  throw OpenSslLoadException(libName);
}

/// Loads libssl as a [NativeLibrary].
NativeLibrary _loadLibSsl() {
  if (Platform.isIOS) {
    return NativeLibrary(DynamicLibrary.process());
  }
  final List<String> libNames;

  if (Platform.isWindows) {
    libNames = const ['libssl-3-x64.dll', 'libssl-1_1-x64.dll'];
  } else if (Platform.isMacOS) {
    // TODO(JKRhb): Check if these are working
    libNames = const [
      '/usr/local/lib/libssl.3.dylib',
      '/usr/local/lib/libssl.1.1.dylib',
      'libssl.3.dylib',
      'libssl.1.1.dylib',
    ];
  } else {
    libNames = const ['libssl.so'];
  }

  return _loadLibrary(libNames, 'libssl');
}

/// Loads libcrypto as a [NativeLibrary].
NativeLibrary _loadLibCrypto() {
  if (Platform.isIOS) {
    return NativeLibrary(DynamicLibrary.process());
  }

  final List<String> libNames;

  if (Platform.isWindows) {
    libNames = const ['libcrypto-3-x64.dll', 'libcrypto-1_1-x64.dll'];
  } else if (Platform.isMacOS) {
    // TODO(JKRhb): Check if these are working
    libNames = const [
      '/usr/local/lib/libcrypto.3.dylib',
      '/usr/local/lib/libcrypto.1.1.dylib',
      'libcrypto.3.dylib',
      'libcrypto.1.1.dylib',
    ];
  } else {
    libNames = const ['libcrypto.so'];
  }

  return _loadLibrary(libNames, 'libssl');
}

/// The global libssl object.
final libSsl = _loadLibSsl();

/// The global libcrypto object.
final libCrypto = _loadLibCrypto();
