// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

/// This [Exception] is thrown when an error occurs within dart_tinydtls.
class DtlsException implements Exception {
  /// Constructor.
  DtlsException(this.message);

  /// The error message of this [DtlsException].
  final String message;

  @override
  String toString() => "DtlsException: $message";
}
