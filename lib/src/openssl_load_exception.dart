// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

/// This [Exception] is thrown if there is an error loading
/// either libssl or libcrypto.
///
/// Using an [Exception] instead of an [Error] allows users
/// to provide a fallback or throw their own [Exception]s
/// if OpenSSL should not be available.
class OpenSslLoadException implements Exception {
  /// The actual error message.
  final String libName;

  /// Constructor.
  OpenSslLoadException(this.libName);

  @override
  String toString() {
    return "OpenSslLoadException: Could not find $libName.";
  }
}
