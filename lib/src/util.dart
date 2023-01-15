// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import 'dart:io';

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

bool _isFatalAlert(int ret) => ret << 8 == SSL3_AL_FATAL;
bool _isCloseNotify(int ret) => ret & 0xff == SSL_AD_CLOSE_NOTIFY;

/// Determines if a DTLS alarm code requires closing the connection.
bool requiresClosing(int ret) => _isFatalAlert(ret) || _isCloseNotify(ret);
