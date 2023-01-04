// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import 'dart:io';
import 'dtls_exception.dart';

/// Represents a DTLS connection to a peer.
///
/// Can be used to [send] data to and to [listen] for incoming data from the
/// peer.
abstract class DtlsConnection extends Stream<Datagram> {
  /// Whether this [DtlsConnection] is still connected.
  bool get connected;

  /// Sends [data] to the endpoint of this [DtlsConnection].
  ///
  /// Returns the number of bytes written. A [DtlsException] is thrown if the
  /// client or server is not connected to the peer anymore.
  int send(List<int> data);

  /// Closes this [DtlsConnection].
  void close();
}
