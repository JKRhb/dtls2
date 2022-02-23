// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'lib.dart';

const pskErrorCode = 0;

typedef _PskCallbackFunction = Uint32 Function(
    Pointer<SSL>, Pointer<Int8>, Pointer<Int8>, Uint32, Pointer<Uint8>, Uint32);

typedef PskCredentialsCallback = PskCredentials Function(
  Uint8List identityHint,
);

/// Credentials used for PSK Cipher Suites consisting of an [identity]
/// and a [preSharedKey].
class PskCredentials {
  Uint8List identity;

  Uint8List preSharedKey;

  PskCredentials({required this.identity, required this.preSharedKey});
}

/// The context contains settings for DTLS session establishment.
///
/// Wrapper for `SSL_CTX`.
class DtlsClientContext {
  Pointer<SSL_CTX> _ctx = libSsl.SSL_CTX_new(libSsl.DTLS_client_method());

  final PskCredentialsCallback? _pskCredentialsCallback;

  void _addRoots(List<Uint8List> certs) {
    if (certs.isEmpty) return;
    final bufLen = certs.map((c) => c.length).reduce(max);
    final buf = malloc.call<Uint8>(bufLen);
    final data = malloc.call<Pointer<Uint8>>(1);
    final store = libSsl.SSL_CTX_get_cert_store(_ctx);

    for (final cert in certs) {
      buf.asTypedList(bufLen).setAll(0, cert);
      data.value = buf;
      final opensslCert = libSsl.d2i_X509(nullptr, data, cert.length);
      libSsl.X509_STORE_add_cert(store, opensslCert);
      libSsl.X509_free(opensslCert);
    }

    malloc.free(data);
    malloc.free(buf);
  }

  /// [verify] enables certificate verification (recommended).
  ///
  /// To allow the verification to succeed, system certificates have to be
  /// imported using [withTrustedRoots], or custom root certificates
  /// in DER format need to be imported with [rootCertificates].
  /// System certificates are available only when OpenSSL is installed by
  /// the system.
  ///
  /// [ciphers] controls the cipher suites offered to the server.
  DtlsClientContext({
    bool verify = true,
    bool withTrustedRoots = false,
    List<Uint8List> rootCertificates = const [],
    String? ciphers,
    PskCredentialsCallback? pskCredentialsCallback,
  }) : _pskCredentialsCallback = pskCredentialsCallback {
    if (withTrustedRoots) {
      libSsl.SSL_CTX_set_default_verify_paths(_ctx);
    }
    _addRoots(rootCertificates);
    libSsl.SSL_CTX_set_verify(
        _ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
    if (ciphers != null) {
      final ciphersStr = ciphers.toNativeUtf8();
      libSsl.SSL_CTX_set_cipher_list(_ctx, ciphersStr.cast());
      malloc.free(ciphersStr);
    }
  }

  /// Free the object. Use after free triggers undefined behavior.
  /// This does not affect any existing [DtlsClientConnection].
  void free() {
    libSsl.SSL_CTX_free(_ctx);
    _ctx = nullptr;
  }
}

/// DTLS client connection.
///
/// A single [RawDatagramSocket] can be used for multiple connections,
/// by sending to different endpoints and processing the sender
/// for each received [Datagram]. A [DtlsClientConnection] can only handle
/// a single connection.
///
/// [incoming] and [outgoing] contain TLS-encrypted data
/// that should be redirected to a [RawDatagramSocket].
///
/// [send] and [received] contain plaintext data
/// that should be passed to the application logic.
///
/// Wrapper for `SSL`.
class DtlsClientConnection {
  static const _bufferSize = (1 << 16); // sizeOf<timeval>() must fit in
  static final Pointer<Uint8> _buffer = malloc.call<Uint8>(_bufferSize);
  Pointer<SSL> _ssl;
  Pointer<BIO> _rbio = libCrypto.BIO_new(libCrypto.BIO_s_mem());
  Pointer<BIO> _wbio = libCrypto.BIO_new(libCrypto.BIO_s_mem());

  final _outgoing = StreamController<Uint8List>();
  Stream<Uint8List> get outgoing => _outgoing.stream;

  final _received = StreamController<Uint8List>();
  Stream<Uint8List> get received => _received.stream;

  final _connected = Completer<void>();

  Timer? _timer;

  final DtlsClientContext _context;

  static Uint8List _determineIdentityHint(
    Pointer<Int8> hint,
    int maxIdentityLength,
  ) {
    if (hint == nullptr) {
      return Uint8List(0);
    }

    final identityHintBytes = <int>[];
    const nullTerminator = 0;
    var index = 0;

    while (index < maxIdentityLength) {
      final currentValue = hint.elementAt(index).value;
      identityHintBytes.add(currentValue);

      if (currentValue == nullTerminator) {
        break;
      }

      index++;
    }

    return Uint8List.fromList(identityHintBytes);
  }

  static int _pskCallback(
      Pointer<SSL> ssl,
      Pointer<Int8> hint,
      Pointer<Int8> identity,
      int maxIdentityLength,
      Pointer<Uint8> psk,
      int maxPskLength) {
    final connection = DtlsClientConnection._connections[ssl.address];
    if (connection == null) {
      throw StateError("No DTLS Connection found for SSL object!");
    }

    final identityHint = _determineIdentityHint(hint, maxIdentityLength);

    final pskCredentials =
        connection._context._pskCredentialsCallback?.call(identityHint);

    if (pskCredentials == null) {
      return pskErrorCode;
    }

    final connectionIdentity = pskCredentials.identity;
    final connectionPsk = pskCredentials.preSharedKey;

    if (connectionIdentity.lengthInBytes > maxIdentityLength ||
        connectionPsk.lengthInBytes > maxPskLength) {
      return pskErrorCode;
    }

    identity
        .asTypedList(connectionIdentity.lengthInBytes)
        .setAll(0, connectionIdentity);
    psk.asTypedList(connectionPsk.lengthInBytes).setAll(0, connectionPsk);
    return connectionPsk.lengthInBytes;
  }

  static final Map<int, DtlsClientConnection> _connections = {};

  /// Create a [DtlsClientConnection] using a [DtlsClientContext].
  /// The [hostname] is used for Server Name Indication
  /// and to verify the certificate.
  DtlsClientConnection({required DtlsClientContext context, String? hostname})
      : _ssl = libSsl.SSL_new(context._ctx),
        _context = context {
    _connections[_ssl.address] = this;
    libSsl.SSL_set_bio(_ssl, _rbio, _wbio);
    libCrypto.BIO_ctrl(_rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);
    libCrypto.BIO_ctrl(_wbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);

    if (hostname != null) {
      final hostnameStr = hostname.toNativeUtf8();
      libCrypto.X509_VERIFY_PARAM_set1_host(
          libSsl.SSL_get0_param(_ssl), hostnameStr.cast(), 0);
      libSsl.SSL_ctrl(_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
          TLSEXT_NAMETYPE_host_name, hostnameStr.cast());
      malloc.free(hostnameStr);
    }

    if (context._pskCredentialsCallback == null) {
      return;
    }

    Pointer<NativeFunction<_PskCallbackFunction>> _callback =
        Pointer.fromFunction(_pskCallback, pskErrorCode);

    libSsl.SSL_set_psk_client_callback(_ssl, _callback);
  }

  void _handleError(int ret, void Function(Exception) errorHandler) {
    final code = libSsl.SSL_get_error(_ssl, ret);
    if (code == SSL_ERROR_SSL) {
      errorHandler(TlsException(
          libSsl.ERR_error_string(libSsl.ERR_get_error(), nullptr)
              .cast<Utf8>()
              .toDartString()));
    } else if (code == SSL_ERROR_ZERO_RETURN) {
      _received.close();
    }
  }

  void incoming(Uint8List input) {
    _buffer.asTypedList(_bufferSize).setAll(0, input);
    libCrypto.BIO_write(_rbio, _buffer.cast(), input.length);
    _maintainState();
  }

  void _maintainState() {
    if (_connected.isCompleted) {
      final ret = libSsl.SSL_read(_ssl, _buffer.cast(), _bufferSize);
      if (ret > 0) {
        _received.add(Uint8List.fromList(_buffer.asTypedList(ret)));
        _maintainOutgoing();
      } else {
        _maintainOutgoing();
        _handleError(ret, _received.addError);
      }
    } else {
      _connect();
    }
  }

  void send(Uint8List data) {
    _buffer.asTypedList(_bufferSize).setAll(0, data);
    final ret = libSsl.SSL_write(_ssl, _buffer.cast(), data.length);
    _maintainOutgoing();
    if (ret < 0) {
      _handleError(ret, (e) => throw e);
    }
  }

  void _connect() {
    final ret = libSsl.SSL_connect(_ssl);
    _maintainOutgoing();
    if (ret == 1) {
      _connected.complete();
    } else if (ret == 0) {
      _connected.completeError(TlsException('handshake shut down'));
    } else {
      _handleError(ret, _connected.completeError);
    }
  }

  Future<void> connect() {
    if (!_connected.isCompleted) {
      _connect();
    }
    return _connected.future;
  }

  void _maintainOutgoing() {
    final ret = libCrypto.BIO_read(_wbio, _buffer.cast(), _bufferSize);
    if (ret > 0) {
      _outgoing.add(Uint8List.fromList(_buffer.asTypedList(ret)));
    }
    _timer?.cancel();
    if (libSsl.SSL_ctrl(_ssl, DTLS_CTRL_GET_TIMEOUT, 0, _buffer.cast()) > 0) {
      _timer = Timer(_buffer.cast<timeval>().ref.duration, _maintainState);
    }
  }

  /// Free the object. Use after free triggers undefined behavior.
  void free() {
    _timer?.cancel();
    libSsl.SSL_free(_ssl);
    _connections.remove(_ssl.address);
    _ssl = nullptr;
    _rbio = nullptr;
    _wbio = nullptr;
  }
}
