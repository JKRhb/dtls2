// Copyright (c) 2024 Jan Romann
// SPDX-License-Identifier: MIT

import "dart:convert";
import "dart:typed_data";

import "package:meta/meta.dart";

/// Base class for certificates usable with OpenSSL.
@immutable
sealed class Certificate {
  const Certificate();

  /// The certificate in serialized form.
  Uint8List get bytes;
}

/// A certificate in PEM format.
final class PemCertificate extends Certificate {
  /// Creates a new [PemCertificate] from a [_certificateString].
  const PemCertificate(this._certificateString);

  final String _certificateString;

  @override
  Uint8List get bytes => utf8.encode(_certificateString);
}

/// A certificate in DER format.
final class DerCertificate extends Certificate {
  /// Creates a new [DerCertificate] from a list of [_bytes].
  const DerCertificate(this._bytes);

  final Uint8List _bytes;

  @override
  Uint8List get bytes => _bytes;
}
