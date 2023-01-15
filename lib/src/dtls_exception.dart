// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

/// This [Exception] is thrown when a DTLS related error occurs.
class DtlsException implements Exception {
  /// Constructor.
  DtlsException(this.message);

  /// The error message of this [DtlsException].
  final String message;

  @override
  String toString() => "DtlsException: $message";
}
