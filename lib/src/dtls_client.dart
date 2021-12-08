// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'lib.dart';

/// The context contains settings for DTLS session establishment.
///
/// Wrapper for `SSL_CTX`.
class DtlsClientContext {
  Pointer<SSL_CTX> _ctx = lib.SSL_CTX_new(lib.DTLS_client_method());

  void _addRoots(List<Uint8List> certs) {
    if (certs.isEmpty) return;
    final bufLen = certs.map((c) => c.length).reduce(max);
    final buf = malloc.call<Uint8>(bufLen);
    final data = malloc.call<Pointer<Uint8>>(1);
    final store = lib.SSL_CTX_get_cert_store(_ctx);

    for (final cert in certs) {
      buf.asTypedList(bufLen).setAll(0, cert);
      data.value = buf;
      final opensslCert = lib.d2i_X509(nullptr, data, cert.length);
      lib.X509_STORE_add_cert(store, opensslCert);
      lib.X509_free(opensslCert);
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
  }) {
    if (withTrustedRoots) {
      lib.SSL_CTX_set_default_verify_paths(_ctx);
    }
    _addRoots(rootCertificates);
    lib.SSL_CTX_set_verify(
        _ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
    if (ciphers != null) {
      final ciphersStr = ciphers.toNativeUtf8();
      lib.SSL_CTX_set_cipher_list(_ctx, ciphersStr.cast());
      malloc.free(ciphersStr);
    }
  }

  /// Free the object. Use after free triggers undefined behavior.
  /// This does not affect any existing [DtlsClientConnection].
  void free() {
    lib.SSL_CTX_free(_ctx);
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
  Pointer<BIO> _rbio = lib.BIO_new(lib.BIO_s_mem());
  Pointer<BIO> _wbio = lib.BIO_new(lib.BIO_s_mem());

  final _outgoing = StreamController<Uint8List>();
  Stream<Uint8List> get outgoing => _outgoing.stream;

  final _received = StreamController<Uint8List>();
  Stream<Uint8List> get received => _received.stream;

  final _connected = Completer<void>();

  Timer? _timer;

  /// Create a [DtlsClientConnection] using a [DtlsClientContext].
  /// The [hostname] is used for Server Name Indication
  /// and to verify the certificate.
  DtlsClientConnection({required DtlsClientContext context, String? hostname})
      : _ssl = lib.SSL_new(context._ctx) {
    lib.SSL_set_bio(_ssl, _rbio, _wbio);
    lib.BIO_ctrl(_rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);
    lib.BIO_ctrl(_wbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);

    if (hostname != null) {
      final hostnameStr = hostname.toNativeUtf8();
      lib.X509_VERIFY_PARAM_set1_host(
          lib.SSL_get0_param(_ssl), hostnameStr.cast(), 0);
      lib.SSL_ctrl(_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
          TLSEXT_NAMETYPE_host_name, hostnameStr.cast());
      malloc.free(hostnameStr);
    }
  }

  void _handleError(int ret, void Function(Exception) errorHandler) {
    final code = lib.SSL_get_error(_ssl, ret);
    if (code == SSL_ERROR_SSL) {
      errorHandler(TlsException(
          lib.ERR_error_string(lib.ERR_get_error(), nullptr)
              .cast<Utf8>()
              .toDartString()));
    } else if (code == SSL_ERROR_ZERO_RETURN) {
      _received.close();
    }
  }

  void incoming(Uint8List input) {
    _buffer.asTypedList(_bufferSize).setAll(0, input);
    lib.BIO_write(_rbio, _buffer.cast(), input.length);
    _maintainState();
  }

  void _maintainState() {
    if (_connected.isCompleted) {
      final ret = lib.SSL_read(_ssl, _buffer.cast(), _bufferSize);
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
    final ret = lib.SSL_write(_ssl, _buffer.cast(), data.length);
    _maintainOutgoing();
    if (ret < 0) {
      _handleError(ret, (e) => throw e);
    }
  }

  void _connect() {
    final ret = lib.SSL_connect(_ssl);
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
    final ret = lib.BIO_read(_wbio, _buffer.cast(), _bufferSize);
    if (ret > 0) {
      _outgoing.add(Uint8List.fromList(_buffer.asTypedList(ret)));
    }
    _timer?.cancel();
    if (lib.SSL_ctrl(_ssl, DTLS_CTRL_GET_TIMEOUT, 0, _buffer.cast()) > 0) {
      _timer = Timer(_buffer.cast<timeval>().ref.duration, _maintainState);
    }
  }

  /// Free the object. Use after free triggers undefined behavior.
  void free() {
    _timer?.cancel();
    lib.SSL_free(_ssl);
    _ssl = nullptr;
    _rbio = nullptr;
    _wbio = nullptr;
  }
}
