// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import 'dart:io';

import 'dtls_connection.dart';
import 'generated/ffi.dart';

/// Creates a string key from an [address] and [port] intended for caching a
/// connection.
String getConnectionKey(InternetAddress address, int port) {
  return "${address.address}:$port";
}

/// Extension for an easier conversion from [timeval] structs to [Duration]
/// objects.
extension DurationTimeval on timeval {
  /// Converts this [timeval] struct to a [Duration] object.
  Duration get duration =>
      Duration(seconds: tv_sec) + Duration(microseconds: tv_usec);
}

/// Extension for making it easier to parse encoded values in OpenSSL's
/// info callback.
extension InfoCallbackUtilities on int {
  /// Determines if the `where` parameter of the info callback is referring to
  /// a DTLS alert.
  bool get isAlert => this & 0x4000 > 0;
}

/// Extension for a factoring out the closing of all client or server
/// [DtlsConnection]s.
extension CloseConnection on Map<String, DtlsConnection> {
  /// Closes all [DtlsConnection]s registered in this [Map].
  ///
  /// When this method is finished, all connections will be/must be removed from
  /// this [Map].
  /// Otherwise, a [StateError] is thrown.
  Future<void> closeConnections() async {
    final copiedConnectionKeys = keys.toList();

    for (final connectionKey in copiedConnectionKeys) {
      await this[connectionKey]?.close();
    }

    if (length > 0) {
      throw StateError("Not all DTLS connections have been closed!");
    }
  }
}
