// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

/// This [Exception] is thrown if there is an error loading
/// either libssl or libcrypto.
///
/// Using an [Exception] instead of an [Error] allows users
/// to provide a fallback or throw their own [Exception]s
/// if OpenSSL should not be available.
class OpenSslLoadException implements Exception {
  /// Constructor.
  OpenSslLoadException(this.libName);

  /// The actual error message.
  final String libName;

  @override
  String toString() {
    return "OpenSslLoadException: Could not find $libName.";
  }
}
