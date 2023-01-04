// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dtls2/src/dtls_connection.dart';
import 'package:ffi/ffi.dart';

import 'dtls_exception.dart';
import 'lib.dart';
import 'psk_credentials.dart';
import 'util.dart';

const _pskErrorCode = 0;

const _bufferSize = (1 << 16);

final Pointer<Uint8> _buffer = malloc.call<Uint8>(_bufferSize);

typedef _PskCallbackFunction = Uint32 Function(
  Pointer<SSL>,
  Pointer<Int8>,
  Pointer<Int8>,
  Uint32,
  Pointer<Uint8>,
  Uint32,
);

extension _DurationTimeval on timeval {
  Duration get duration =>
      Duration(seconds: tv_sec) + Duration(microseconds: tv_usec);
}

/// Client for connecting to DTLS Servers and sending UDP packets with encrpyted
/// payloads afterwards.
///
/// Uses a [RawDatagramSocket] for connection establishment and sending. This
/// socket can either be created by the [DtlsClient] itself, using the [bind]
/// method, or provided by the user with the regular constructor.
///
/// Connections to a peer are established using the [connect] method.
/// If the connection is successful, a [DtlsConnection] is returned that can be
/// used for sending the actual application data.
///
/// Closing the [DtlsClient] with the [close] method also closes all existing
/// [DtlsConnection]s.
class DtlsClient {
  /// Creates a new [DtlsClient] that uses a pre-existing [RawDatagramSocket]
  /// and a [_context] for establishing [DtlsConnection]s.
  DtlsClient(this._socket, this._context) {
    _startListening();
  }

  /// Binds a [DtlsClient] to the given [host] and [port], using the passed in
  /// [_context] for establishing [DtlsConnection]s.
  ///
  /// Uses a [RawDatagramSocket] internally and passes the [host], [port],
  /// [reusePort], [reuseAddress], and [ttl] arguments to it.
  static Future<DtlsClient> bind(
    dynamic host,
    int port,
    DtlsClientContext context, {
    bool reuseAddress = true,
    bool reusePort = false,
    int ttl = 1,
  }) async {
    final socket = await RawDatagramSocket.bind(
      host,
      port,
      reuseAddress: reuseAddress,
      reusePort: reusePort,
      ttl: ttl,
    );

    return DtlsClient(socket, context).._externalSocket = false;
  }

  void _startListening() {
    _socket.listen((event) async {
      if (event == RawSocketEvent.read) {
        final data = _socket.receive();
        if (data != null) {
          for (final connection in _connections.values) {
            _incoming(data.data, connection);
          }
        }
      }
    });
  }

  bool _closed = false;

  bool _externalSocket = true;

  final RawDatagramSocket _socket;

  final DtlsClientContext _context;

  /// Maps combinations of [InternetAddress]es and ports to
  /// [_DtlsClientConnection]s.
  static final Map<String, _DtlsClientConnection> _connections = {};

  /// Maps OpenSSL sessions to combinations of [InternetAddress]es and ports.
  static final Map<int, String> _sessions = {};

  /// Closes this [DtlsClient].
  ///
  /// [RawDatagramSocket]s that have been passed in by the user are only closed
  /// if [closeExternalSocket] is set to `true`.
  void close({bool closeExternalSocket = false}) {
    if (_closed) {
      return;
    }

    for (final connection in _connections.values) {
      connection.close(closedByClient: true);
    }

    _connections.clear();
    _sessions.clear();
    if (!_externalSocket || closeExternalSocket) {
      _socket.close();
    }

    _closed = true;
  }

  /// Establishes a [DtlsConnection] with a peer using the given [address]
  /// and [port].
  ///
  /// If a [DtlsConnection] to a peer with the given [address] and [port]
  /// already exists, that connection will be reused instead of opening a new
  /// one. If you want to establish a connection using different credentials,
  /// then you need to close the old connection first.
  Future<DtlsConnection> connect(
    InternetAddress address,
    int port, {
    String? hostname,
  }) async {
    final key = getConnectionKey(address, port);

    final existingConnection = _connections[key];

    if (existingConnection != null && !existingConnection._closed) {
      return existingConnection;
    }

    final connection = await _DtlsClientConnection.connect(
      this,
      hostname,
      address,
      port,
      _context,
    );

    return connection;
  }

  void _incoming(Uint8List input, _DtlsClientConnection connection) {
    _buffer.asTypedList(_bufferSize).setAll(0, input);
    libCrypto.BIO_write(connection._rbio, _buffer.cast(), input.length);
    connection._maintainState();
  }

  int _send(_DtlsClientConnection _dtlsClientConnection, List<int> data) {
    _buffer.asTypedList(_bufferSize).setAll(0, data);
    final ret = libSsl.SSL_write(
        _dtlsClientConnection._ssl, _buffer.cast(), data.length);
    _dtlsClientConnection._maintainOutgoing();
    if (ret < 0) {
      _dtlsClientConnection._handleError(ret, (e) => throw e);
    }
    return ret;
  }
}

class _DtlsClientConnection extends Stream<Datagram> implements DtlsConnection {
  /// Create a [_DtlsClientConnection] using a [DtlsClientContext].
  /// The [hostname] is used for Server Name Indication
  /// and to verify the certificate.
  _DtlsClientConnection(
    this._dtlsClient,
    String? hostname,
    this._address,
    this._port,
    this._context,
    this._ssl,
  ) {
    libSsl.SSL_set_bio(_ssl, _rbio, _wbio);
    libCrypto
      ..BIO_ctrl(_rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr)
      ..BIO_ctrl(_wbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);

    if (hostname != null) {
      final hostnameStr = hostname.toNativeUtf8();
      libCrypto.X509_VERIFY_PARAM_set1_host(
          libSsl.SSL_get0_param(_ssl), hostnameStr.cast(), nullptr);
      libSsl.SSL_ctrl(_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
          TLSEXT_NAMETYPE_host_name, hostnameStr.cast());
      malloc.free(hostnameStr);
    }

    libSsl.SSL_CTX_set_info_callback(
      _context._ctx,
      Pointer.fromFunction(_infoCallback),
    );

    if (_context._pskCredentialsCallback == null) {
      return;
    }

    final Pointer<NativeFunction<_PskCallbackFunction>> _callback =
        Pointer.fromFunction(_pskCallback, _pskErrorCode);

    libSsl.SSL_set_psk_client_callback(_ssl, _callback);
  }

  static Future<_DtlsClientConnection> connect(
    DtlsClient dtlsClient,
    String? hostname,
    InternetAddress address,
    int port,
    DtlsClientContext context,
  ) {
    final ssl = libSsl.SSL_new(context._ctx);
    final connection = _DtlsClientConnection(
        dtlsClient, hostname, address, port, context, ssl);
    final key = getConnectionKey(address, port);
    DtlsClient._connections[key] = connection;
    DtlsClient._sessions[ssl.address] = key;
    return connection._connect();
  }

  bool _closed = false;

  Pointer<SSL> _ssl;

  final InternetAddress _address;

  final int _port;

  final Completer<_DtlsClientConnection> _connectCompleter = Completer();

  Pointer<BIO> _rbio = libCrypto.BIO_new(libCrypto.BIO_s_mem());
  Pointer<BIO> _wbio = libCrypto.BIO_new(libCrypto.BIO_s_mem());

  final _received = StreamController<Datagram>();

  bool _connected = false;

  @override
  bool get connected => _connected;

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
    final address = DtlsClient._sessions[ssl.address];
    final connection = DtlsClient._connections[address];

    if (connection == null) {
      throw StateError("No DTLS Connection found for SSL object!");
    }

    final identityHint = _determineIdentityHint(hint, maxIdentityLength);

    final pskCredentials =
        connection._context._pskCredentialsCallback?.call(identityHint);

    if (pskCredentials == null) {
      return _pskErrorCode;
    }

    final connectionIdentity = pskCredentials.identity;
    final connectionPsk = pskCredentials.preSharedKey;

    if (connectionIdentity.lengthInBytes > maxIdentityLength ||
        connectionPsk.lengthInBytes > maxPskLength) {
      return _pskErrorCode;
    }

    identity
        .asTypedList(connectionIdentity.lengthInBytes)
        .setAll(0, connectionIdentity);
    psk.asTypedList(connectionPsk.lengthInBytes).setAll(0, connectionPsk);
    return connectionPsk.lengthInBytes;
  }

  static bool _isFatalAlert(int ret) => ret << 8 == SSL3_AL_FATAL;
  static bool _isCloseNotify(int ret) => ret & 0xff == SSL_AD_CLOSE_NOTIFY;
  static bool _requiresClosing(int ret) =>
      _isFatalAlert(ret) || _isCloseNotify(ret);

  static void _infoCallback(
    Pointer<SSL> ssl,
    int where,
    int ret,
  ) {
    final address = DtlsClient._sessions[ssl.address];
    final connection = DtlsClient._connections[address];

    if (connection == null) {
      throw StateError("No DTLS Connection found for SSL object!");
    }

    if (_requiresClosing(ret)) {
      connection.close();
    }
  }

  final DtlsClient _dtlsClient;

  void _handleError(int ret, void Function(Exception) errorHandler) {
    final code = libSsl.SSL_get_error(_ssl, ret);
    if (code == SSL_ERROR_SSL) {
      errorHandler(TlsException(
          libCrypto.ERR_error_string(libCrypto.ERR_get_error(), nullptr)
              .cast<Utf8>()
              .toDartString()));
    } else if (code == SSL_ERROR_ZERO_RETURN) {
      close();
    }
  }

  void _connectToPeer() {
    final ret = libSsl.SSL_connect(_ssl);
    _maintainOutgoing();
    if (ret == 1) {
      _connected = true;
      _connectCompleter.complete(this);
    } else if (ret == 0) {
      _connectCompleter.completeError(TlsException('handshake shut down'));
    } else {
      _handleError(ret, _connectCompleter.completeError);
    }
  }

  Future<_DtlsClientConnection> _connect() {
    if (!_connectCompleter.isCompleted) {
      _connectToPeer();
    }
    return _connectCompleter.future;
  }

  @override
  int send(List<int> data) {
    if (!_connected) {
      throw DtlsException("Sending failed: Not connected!");
    }

    return _dtlsClient._send(this, data);
  }

  /// Closes the connection and frees all allocated resources.
  ///
  /// After the connection is closed, trying to send will throw a
  /// [DtlsException].
  @override
  Future<void> close({bool closedByClient = false}) async {
    if (_closed) {
      return;
    }

    _timer?.cancel();
    await _received.close();

    if (!closedByClient) {
      // This distinction is made to avoid concurrent modification errors.
      final address = DtlsClient._sessions.remove(_ssl.address);
      DtlsClient._connections.remove(address);
    }

    libSsl
      ..SSL_free(_ssl)
      ..BIO_free(_rbio)
      ..BIO_free(_wbio);
    _ssl = nullptr;
    _rbio = nullptr;
    _wbio = nullptr;

    _closed = true;
    _connected = false;
  }

  void _maintainOutgoing() {
    final ret = libCrypto.BIO_read(_wbio, _buffer.cast(), _bufferSize);
    if (ret > 0) {
      _dtlsClient._socket.send(_buffer.asTypedList(ret), _address, _port);
    }
    _timer?.cancel();
    if (libSsl.SSL_ctrl(_ssl, DTLS_CTRL_GET_TIMEOUT, 0, _buffer.cast()) > 0) {
      _timer = Timer(_buffer.cast<timeval>().ref.duration, _maintainState);
    }
  }

  void _maintainState() {
    if (_connectCompleter.isCompleted) {
      final ret = libSsl.SSL_read(_ssl, _buffer.cast(), _bufferSize);
      if (ret > 0) {
        final data = Uint8List.fromList(_buffer.asTypedList(ret));
        final datagram = Datagram(data, _address, _port);
        _received.add(datagram);
        _maintainOutgoing();
      } else {
        _maintainOutgoing();
        _handleError(ret, _received.addError);
      }
    } else {
      _connectToPeer();
    }
  }

  @override
  StreamSubscription<Datagram> listen(void Function(Datagram event)? onData,
          {Function? onError, void Function()? onDone, bool? cancelOnError}) =>
      _received.stream.listen(onData,
          onError: onError, onDone: onDone, cancelOnError: cancelOnError);
}

/// The context contains settings for DTLS session establishment.
///
/// Wrapper for `SSL_CTX`.
class DtlsClientContext {
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
      libSsl
        ..X509_STORE_add_cert(store, opensslCert)
        ..X509_free(opensslCert);
    }

    malloc
      ..free(data)
      ..free(buf);
  }

  /// Free the object. Use after free triggers undefined behavior.
  /// This does not affect any existing [_DtlsClientConnection].
  void free() {
    libSsl.SSL_CTX_free(_ctx);
    _ctx = nullptr;
  }
}
