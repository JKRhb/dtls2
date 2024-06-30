// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

/// Function signature for a callback function for retrieving/generating
/// [PskCredentials].
///
/// Servers might provide an [identityHint] that contains information on how
/// to generate the credentials.
typedef PskCredentialsCallback = PskCredentials Function(
  String? identityHint,
);

/// Credentials used for PSK Cipher Suites consisting of an [identity]
/// and a [preSharedKey].
class PskCredentials {
  /// Constructor
  PskCredentials({required this.identity, required this.preSharedKey});

  /// The identity used with the [preSharedKey].
  Iterable<int> identity;

  /// The actual pre-shared key.
  Iterable<int> preSharedKey;
}
