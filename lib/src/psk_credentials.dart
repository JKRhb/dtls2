// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import 'dart:typed_data';

/// Function signature for a callback function for retrieving/generating
/// [PskCredentials].
///
/// As the format of the [identityHint] is not well-defined, this parameter
/// can probably be ignored in most cases, when both the identity and the key
/// are known in advance.
typedef PskCredentialsCallback = PskCredentials Function(
  Uint8List identityHint,
);

/// Credentials used for PSK Cipher Suites consisting of an [identity]
/// and a [preSharedKey].
class PskCredentials {
  /// The identity used with the [preSharedKey].
  Uint8List identity;

  /// The actual pre-shared key.
  Uint8List preSharedKey;

  /// Constructor
  PskCredentials({required this.identity, required this.preSharedKey});
}
