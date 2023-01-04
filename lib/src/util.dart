// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import 'dart:io';

/// Creates a string key from an [address] and [port] intended for caching a
/// connection.
String getConnectionKey(InternetAddress address, int port) {
  return "${address.address}:$port";
}
