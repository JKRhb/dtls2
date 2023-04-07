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
  Future<void> close();

  /// Indicates the current state of this [DtlsConnection].
  ConnectionState get state;
}

/// Indicates the
enum ConnectionState {
  /// The connection has not been initialized yet.
  uninitialized,

  /// The DTLS handshake is currently being performed.
  handshake,

  /// The handshake was successful, the [DtlsConnection] has been established.
  connected,

  /// The [DtlsConnection] has been shutdown.
  ///
  /// This can either be due to an orderly shutdown or due to an error during
  /// the handshake process.
  shutdown,
}
