// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import "dart:io";
import "package:dtls2/src/dtls_exception.dart";

/// Represents a DTLS connection to a peer.
///
/// Can be used to [send] data to and to [listen] for incoming data from the
/// peer.
mixin DtlsConnection on Stream<Datagram> {
  /// Whether this [DtlsConnection] is still connected.
  bool get connected => state == ConnectionState.connected;

  /// Whether this [DtlsConnection] has been shut down.
  bool get closed => state == ConnectionState.closed;

  /// Whether this [DtlsConnection] is still in the process of being set up.
  bool get inHandshake => state == ConnectionState.handshake;

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

/// Describes the different stages of a [DtlsConnection]'s lifecycle.
enum ConnectionState {
  /// The connection has not been initialized yet.
  uninitialized(canBeClosed: true),

  /// The DTLS handshake is currently being performed.
  handshake(canBeClosed: true),

  /// The handshake was successful, the [DtlsConnection] has been established.
  connected(canBeClosed: true),

  /// The [DtlsConnection] is in the process of being shut down.
  ///
  /// Before the state [closed] is reached, the connection will perform a clean
  /// up of allocated resources and remove itself from the client or server it
  /// is associated with.
  closing(canBeClosed: false),

  /// The [DtlsConnection] has been shut down.
  ///
  /// This can either be due to an orderly shutdown or due to an error during
  /// the handshake process.
  closed(canBeClosed: false),
  ;

  /// Constructor for a new [ConnectionState].
  ///
  /// Each [ConnectionState] needs to indicate whether it [canBeClosed] in order
  /// to not close a [DtlsConnection] twice.
  const ConnectionState({required this.canBeClosed});

  /// Indicates if a closing procedure can be triggered from this
  /// [ConnectionState].
  final bool canBeClosed;
}
