// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import "dart:async";

/// This [Exception] is thrown when a DTLS related error occurs.
class DtlsException implements Exception {
  /// Constructor.
  DtlsException(this.message);

  /// The error message of this [DtlsException].
  final String message;

  @override
  String toString() => "DtlsException: $message";
}

/// A [DtlsException] that is thrown when a DTLS handshake fails.
class DtlsHandshakeException extends DtlsException {
  /// Constructor.
  DtlsHandshakeException(super.message);

  @override
  String toString() => "DtlsHandshakeException: $message";
}

/// [DtlsException] that indicates that a timeout has occured.
class DtlsTimeoutException extends DtlsException implements TimeoutException {
  /// Constructor.
  DtlsTimeoutException(super.message, this.duration);

  @override
  final Duration duration;

  @override
  String toString() => "DtlsTimeoutException after $duration: $message";
}
