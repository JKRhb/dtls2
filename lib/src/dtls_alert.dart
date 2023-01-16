// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import 'dart:collection';

/// The possible DTLS alert levels.
///
/// Can describe be a DTLS [warning] or [fatal] error.
enum AlertLevel {
  /// Describes a warning. Only requires a connection to be closed in the case
  /// of a [AlertDescription.closeNotify] alert.
  warning(1, "Warning"),

  /// Describes a fatal error, which always causes a connection to be closed.
  fatal(2, "Fatal Error");

  /// Constuctor.
  const AlertLevel(this._code, this._stringValue);

  final int _code;

  final String _stringValue;

  static final _registry =
      HashMap.fromEntries(values.map((value) => MapEntry(value._code, value)));

  /// Creates an [AlertDescription] from a numeric [code].
  static AlertLevel? fromCode(int code) => _registry[code];

  @override
  String toString() => "Alert Level '$_stringValue'";
}

/// The description component of a [DtlsAlert].
///
/// Can either be the description of a warning or a fatal error.
enum AlertDescription {
  // TODO(JKRhb): Add missing alert codes.

  /// Indicates that the peer has closed their connection.
  ///
  /// This type of alert always causes a DTLS connection to be closed.
  closeNotify(0, "close_notify"),

  /// An inappropriate message was received.
  ///
  /// This alert is always fatal and should never be observed in communication
  /// between proper implementations.
  unexceptedMessage(10, "unexpected_message"),

  /// This alert is returned if a record is received with an incorrect MAC.
  ///
  /// This message is always fatal and should
  /// never be observed in communication between proper implementations
  /// (except when messages were corrupted in the network).
  badRecordMac(20, "bad_record_mac"),

  /// A TLSCiphertext record was received that had a length more than 2^14+2048
  /// bytes, or a record decrypted to a TLSCompressed record with more than
  /// 2^14+1024 bytes.
  ///
  /// This message is always fatal and should never be observed in communication
  /// between proper implementations (except when messages were corrupted in the
  /// network).
  recordOverflow(22, "record_overflow"),

  /// The decompression function received improper input (e.g., data that would
  /// expand to excessive length).
  ///
  /// This message is always fatal and should never be observed in communication
  /// between proper implementations.
  decompressionFailure(30, "decompression_failure"),

  /// Indicates that the sender was unable to negotiate an acceptable set of
  /// security parameters given the options available.
  ///
  /// This is a fatal error.
  handshakeFailure(40, "handshake_failure"),

  /// A certificate was corrupt, contained signatures that did not
  /// verify correctly, etc.
  badCertificate(42, "bad_certificate"),

  /// A certificate was of an unsupported type.
  unsupportedCertificate(43, "unsupported_certificate"),

  /// A certificate was revoked by its signer.
  certificateRevoked(44, "certificate_revoked"),

  /// A certificate has expired or is not currently valid.
  certificateExpired(45, "certificate_expired"),

  /// Some other (unspecified) issue arose in processing the certificate,
  /// rendering it unacceptable.
  certificateUnknown(46, "certificate_unknown"),

  /// A field in the handshake was out of range or inconsistent with other
  /// fields.
  ///
  /// This message is always fatal.
  illegalParameter(47, "illegal_parameter"),

  /// A valid certificate chain or partial chain was received, but the
  /// certificate was not accepted because the CA certificate could not
  /// be located or couldn't be matched with a known, trusted CA.
  ///
  /// This message is always fatal.
  unknownCa(48, "unknown_ca"),

  /// A valid certificate was received, but when access control was
  /// applied, the sender decided not to proceed with negotiation.  This
  /// message is always fatal.
  accessDenied(49, "access_denied"),

  /// A message could not be decoded because some field was out of the
  /// specified range or the length of the message was incorrect.
  ///
  /// This message is always fatal and should never be observed in
  /// communication between proper implementations (except when messages
  /// were corrupted in the network).
  decodeError(50, "decode_error"),

  /// A handshake cryptographic operation failed, including being unable
  /// to correctly verify a signature or validate a Finished message.
  ///
  /// This message is always fatal.
  decryptError(51, "decrypt_error"),

  /// The protocol version the client has attempted to negotiate is recognized
  /// but not supported. (For example, old protocol versions might be avoided
  /// for security reasons.)
  ///
  /// This message is always fatal.
  protocolVersion(70, "protocol_version"),

  /// Returned instead of handshake_failure when a negotiation has failed
  /// specifically because the server requires ciphers more secure than those
  /// supported by the client.
  ///
  /// This message is always fatal.
  insufficientSecurity(71, "insufficient_security"),

  /// An internal error unrelated to the peer or the correctness of the protocol
  /// (such as a memory allocation failure) makes it impossible to continue.
  ///
  /// This message is always fatal.
  internalError(80, "internal_error"),

  /// This handshake is being canceled for some reason unrelated to a protocol
  /// failure.
  ///
  /// This alert should be followed by a [closeNotify].
  ///
  /// This message is generally a warning.
  userCanceled(90, "user_canceled"),

  /// Sent by the client in response to a hello request or by the server in
  /// response to a client hello after initial handshaking.
  ///
  /// This message is always a warning.
  noRenegotiation(100, "no_renegotiation"),

  /// Sent by clients that receive an extended server hello containing an
  /// extension that they did not put in the corresponding client
  /// hello.
  ///
  /// This message is always fatal.
  unsupportedExtension(110, "unsupported_extension"),
  ;

  /// Constructor.
  const AlertDescription(
    this._code,
    this._identifier,
  );

  final int _code;

  final String _identifier;

  static final _registry =
      HashMap.fromEntries(values.map((value) => MapEntry(value._code, value)));

  /// Creates an [AlertDescription] from a numeric [code].
  static AlertDescription? fromCode(int code) => _registry[code];

  @override
  String toString() {
    return _identifier;
  }
}

/// Describes an alert as specified by the DTLS specification.
///
/// Consists of an [alertLevel] and a [alertDescription].
class DtlsAlert {
  /// The alert level of this alert.
  final AlertLevel alertLevel;

  /// The description of this alert.
  final AlertDescription alertDescription;

  /// Constructor.
  DtlsAlert(this.alertLevel, this.alertDescription);

  /// Generates a new [DtlsAlert] from the [code] passed in OpenSSL's info
  /// callback.
  ///
  /// Returns `null` if the [alertLevel] or the [alertDescription] cannot be
  /// parsed.
  static DtlsAlert? fromCode(int code) {
    final alertLevel = AlertLevel.fromCode(code >> 8);
    final alertDescription = AlertDescription.fromCode(code & 0xff);

    if (alertLevel == null || alertDescription == null) {
      return null;
    }

    return DtlsAlert(alertLevel, alertDescription);
  }

  /// Indicates if this [DtlsAlert] demands closing the connection.
  // TODO(JKRhb): Check criteria for closing.
  bool get requiresClosing =>
      alertLevel == AlertLevel.fatal ||
      alertDescription == AlertDescription.closeNotify;

  @override
  String toString() =>
      "DtlsEvent with $alertLevel and description '$alertDescription'.";
}
