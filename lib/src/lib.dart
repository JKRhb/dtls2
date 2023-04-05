// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import "dart:ffi";
import "dart:io";

import "package:dtls2/src/generated/ffi.dart";
import "package:dtls2/src/openssl_load_exception.dart";

OpenSsl _loadLibrary(List<String> libNames, String libName) {
  for (final libName in libNames) {
    try {
      return OpenSsl(DynamicLibrary.open(libName));
      // ignore: avoid_catching_errors
    } on ArgumentError {
      continue;
    }
  }

  throw OpenSslLoadException(libName);
}

/// Loads libssl as an [OpenSsl] object.
OpenSsl _loadLibSsl() {
  if (Platform.isIOS) {
    return OpenSsl(DynamicLibrary.process());
  }
  final List<String> libNames;

  if (Platform.isWindows) {
    libNames = const ["libssl-3-x64.dll", "libssl-1_1-x64.dll"];
  } else if (Platform.isMacOS) {
    libNames = const [
      "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
      "/usr/local/opt/openssl@1.1/lib/libssl.1.1.dylib",
      "libssl.3.dylib",
      "libssl.1.1.dylib",
    ];
  } else {
    libNames = const ["libssl.so"];
  }

  return _loadLibrary(libNames, "libssl");
}

/// Loads libcrypto as an [OpenSsl] object.
OpenSsl _loadLibCrypto() {
  if (Platform.isIOS) {
    return OpenSsl(DynamicLibrary.process());
  }

  final List<String> libNames;

  if (Platform.isWindows) {
    libNames = const ["libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll"];
  } else if (Platform.isMacOS) {
    libNames = const [
      "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
      "/usr/local/opt/openssl@1.1/lib/libcrypto.1.1.dylib",
      "libcrypto.3.dylib",
      "libcrypto.1.1.dylib",
    ];
  } else {
    libNames = const ["libcrypto.so"];
  }

  return _loadLibrary(libNames, "libcrypto");
}

/// The global libssl object.
final _libSsl = _loadLibSsl();

/// The global libcrypto object.
final _libCrypto = _loadLibCrypto();

OpenSsl _loadOpenSsl(DynamicLibrary? dynamicLibrary, OpenSsl defaultLibrary) {
  if (dynamicLibrary == null) {
    return defaultLibrary;
  }

  return OpenSsl(dynamicLibrary);
}

/// Tries to load libcrypto from a [dynamicLibrary].
///
/// If that fails, the function tries to load libcrypto from a default location.
OpenSsl loadLibCrypto(DynamicLibrary? dynamicLibrary) =>
    _loadOpenSsl(dynamicLibrary, _libCrypto);

/// Tries to load libssl from a [dynamicLibrary].
///
/// If that fails, the function tries to load libssl from a default location.
OpenSsl loadLibSsl(DynamicLibrary? dynamicLibrary) =>
    _loadOpenSsl(dynamicLibrary, _libSsl);
