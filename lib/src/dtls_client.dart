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

import 'buffer.dart';
import 'dtls_alert.dart';
import 'dtls_exception.dart';
import 'generated/ffi.dart';
import 'lib.dart' as lib;
import 'psk_credentials.dart';
import 'util.dart';

const _pskErrorCode = 0;

typedef _PskCallbackFunction = UnsignedInt Function(
  Pointer<SSL>,
  Pointer<Char>,
  Pointer<Char>,
  UnsignedInt,
  Pointer<UnsignedChar>,
  UnsignedInt,
);

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
  /// Creates a new [DtlsClient] that uses a pre-existing [RawDatagramSocket].
  ///
  /// If you want to load [libSsl] or [libCrypto] yourself (e.g., from a custom
  /// path), you can pass custom [OpenSsl] objects to this constructor.
  DtlsClient(
    this._socket, {
    DynamicLibrary? libSsl,
    DynamicLibrary? libCrypto,
  })  : _libSsl = _loadOpenSsl(libSsl) ?? lib.libSsl,
        _libCrypto = _loadOpenSsl(libCrypto) ?? lib.libCrypto {
    _startListening();
  }

  /// Binds a [DtlsClient] to the given [host] and [port].
  ///
  /// Uses a [RawDatagramSocket] internally and passes the [host], [port],
  /// [reusePort], [reuseAddress], and [ttl] arguments to it.
  ///
  /// If you want to load [libSsl] or [libCrypto] yourself (e.g., from a custom
  /// path), you can pass custom [OpenSsl] objects to this constructor.
  static Future<DtlsClient> bind(
    dynamic host,
    int port, {
    bool reuseAddress = true,
    bool reusePort = false,
    int ttl = 1,
    DynamicLibrary? libSsl,
    DynamicLibrary? libCrypto,
  }) async {
    final socket = await RawDatagramSocket.bind(
      host,
      port,
      reuseAddress: reuseAddress,
      reusePort: reusePort,
      ttl: ttl,
    );

    return DtlsClient(socket, libSsl: libSsl, libCrypto: libCrypto)
      .._externalSocket = false;
  }

  void _startListening() {
    _socket.listen((event) async {
      switch (event) {
        case RawSocketEvent.read:
          final data = _socket.receive();
          if (data != null) {
            final key = getConnectionKey(data.address, data.port);
            final connection = _connectionCache[key];

            if (connection != null) {
              connection._incoming(data.data);
            }
          }

          break;
        case RawSocketEvent.closed:
          await close();
          break;
        case RawSocketEvent.readClosed:
        case RawSocketEvent.write:
          break;
      }
    });
  }

  bool _closed = false;

  bool _externalSocket = true;

  final RawDatagramSocket _socket;

  /// Maps combinations of [InternetAddress]es and ports to
  /// [_DtlsClientConnection]s to enable caching for this client.
  final Map<String, _DtlsClientConnection> _connectionCache = {};

  /// Maps OpenSSL sessions to [_DtlsClientConnection]s.
  static final Map<int, _DtlsClientConnection> _connections = {};

  final OpenSsl _libSsl;

  final OpenSsl _libCrypto;

  static OpenSsl? _loadOpenSsl(DynamicLibrary? dynamicLibrary) {
    if (dynamicLibrary == null) {
      return null;
    }

    return OpenSsl(dynamicLibrary);
  }

  /// Closes this [DtlsClient].
  ///
  /// [RawDatagramSocket]s that have been passed in by the user are only closed
  /// if [closeExternalSocket] is set to `true`.
  Future<void> close({bool closeExternalSocket = false}) async {
    if (_closed) {
      return;
    }

    for (final connection in _connectionCache.values) {
      _connections.remove(connection._ssl.address);
      await connection.close(closedByClient: true);
    }

    _connectionCache.clear();
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
  ///
  /// If a [timeout] duration is defined, a [TimeoutException] will be thrown
  /// if no connection could be established within the given time period.
  Future<DtlsConnection> connect(
    InternetAddress address,
    int port,
    DtlsClientContext context, {
    String? hostname,
    Duration? timeout,
  }) async {
    final key = getConnectionKey(address, port);

    final existingConnection = _connectionCache[key];

    if (existingConnection != null && !existingConnection._closed) {
      return existingConnection;
    }

    final connection = _DtlsClientConnection(
      this,
      hostname,
      address,
      port,
      context._generateSslContext(_libSsl),
      context._pskCredentialsCallback,
      _libCrypto,
      _libSsl,
    );
    await connection._checkSslCiphers();

    _connectionCache[key] = connection;
    DtlsClient._connections[connection._ssl.address] = connection;

    return connection._connect(timeout: timeout);
  }

  int _send(_DtlsClientConnection dtlsClientConnection, List<int> data) {
    buffer.asTypedList(bufferSize).setAll(0, data);
    final ret = _libSsl.SSL_write(
        dtlsClientConnection._ssl, buffer.cast(), data.length);
    dtlsClientConnection._maintainOutgoing();
    if (ret < 0) {
      dtlsClientConnection._handleError(ret, (e) => throw e);
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
    Pointer<SSL_CTX> sslContext,
    this._pskCredentialsCallback,
    this._libCrypto,
    this._libSsl,
  )   : _ssl = _libSsl.SSL_new(sslContext),
        _rbio = _libCrypto.BIO_new(_libCrypto.BIO_s_mem()),
        _wbio = _libCrypto.BIO_new(_libCrypto.BIO_s_mem()) {
    _libSsl.SSL_set_bio(_ssl, _rbio, _wbio);
    _libCrypto
      ..BIO_ctrl(_rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr)
      ..BIO_ctrl(_wbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);

    if (hostname != null) {
      final hostnameStr = hostname.toNativeUtf8();
      _libCrypto.X509_VERIFY_PARAM_set1_host(
          _libSsl.SSL_get0_param(_ssl), hostnameStr.cast(), hostnameStr.length);
      _libSsl.SSL_ctrl(_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
          TLSEXT_NAMETYPE_host_name, hostnameStr.cast());
      malloc.free(hostnameStr);
    }

    _libSsl
      ..SSL_CTX_set_info_callback(
        sslContext,
        Pointer.fromFunction(_infoCallback),
      )
      ..SSL_CTX_free(sslContext);

    if (_pskCredentialsCallback == null) {
      return;
    }

    final Pointer<NativeFunction<_PskCallbackFunction>> callback =
        Pointer.fromFunction(_pskCallback, _pskErrorCode);

    _libSsl.SSL_set_psk_client_callback(_ssl, callback);
  }

  bool _closed = false;

  final Pointer<SSL> _ssl;

  final InternetAddress _address;

  final int _port;

  final Completer<_DtlsClientConnection> _connectCompleter = Completer();

  final Pointer<BIO> _rbio;

  final Pointer<BIO> _wbio;

  final _received = StreamController<Datagram>();

  bool _connected = false;

  final PskCredentialsCallback? _pskCredentialsCallback;

  @override
  bool get connected => _connected;

  Timer? _timer;

  final OpenSsl _libSsl;

  final OpenSsl _libCrypto;

  /// Throws a [DtlsException] if no ciphers are available for this connection
  /// attempt.
  ///
  /// If this is the case, the allocated resources are cleaned up by calling the
  /// [close] method.
  Future<void> _checkSslCiphers() async {
    // TODO(JKRhb): Could this method get called from a constructor?
    final ciphersPointer = _libSsl.SSL_get1_supported_ciphers(_ssl);

    if (ciphersPointer == nullptr) {
      await close(closedByClient: true);
      throw DtlsException(
        "No ciphers available. "
        "If you are using PSK cipher suites, check you have defined a "
        "pskCredentialsCallback.",
      );
    }
  }

  static String? _determineIdentityHint(Pointer<Char> hint) {
    if (hint == nullptr) {
      return null;
    }

    return hint.cast<Utf8>().toDartString();
  }

  static int _pskCallback(
      Pointer<SSL> ssl,
      Pointer<Char> hint,
      Pointer<Char> identity,
      int maxIdentityLength,
      Pointer<UnsignedChar> psk,
      int maxPskLength) {
    final connection = DtlsClient._connections[ssl.address];

    if (connection == null) {
      throw StateError("No DTLS Connection found for SSL object!");
    }

    final identityHint = _determineIdentityHint(hint);

    final pskCredentials =
        connection._pskCredentialsCallback?.call(identityHint);

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
        .cast<Uint8>()
        .asTypedList(connectionIdentity.lengthInBytes)
        .setAll(0, connectionIdentity);
    psk
        .cast<Uint8>()
        .asTypedList(connectionPsk.lengthInBytes)
        .setAll(0, connectionPsk);
    return connectionPsk.lengthInBytes;
  }

  void _handleAlert(DtlsAlert event) {
    if (event.requiresClosing) {
      close();
    }
  }

  static void _infoCallback(
    Pointer<SSL> ssl,
    int where,
    int ret,
  ) {
    if (!where.isAlert) {
      return;
    }

    final connection = DtlsClient._connections[ssl.address];

    if (connection == null) {
      throw StateError("No DTLS Connection found for SSL object!");
    }

    final event = DtlsAlert.fromCode(ret);

    if (event != null) {
      connection._handleAlert(event);
    }
  }

  final DtlsClient _dtlsClient;

  void _handleError(int ret, void Function(Exception) errorHandler) {
    final code = _libSsl.SSL_get_error(_ssl, ret);
    if (code == SSL_ERROR_SSL) {
      errorHandler(DtlsException(
          _libCrypto.ERR_error_string(_libCrypto.ERR_get_error(), nullptr)
              .cast<Utf8>()
              .toDartString()));
    } else if (code == SSL_ERROR_ZERO_RETURN) {
      close();
    }
  }

  void _connectToPeer() {
    final ret = _libSsl.SSL_connect(_ssl);
    _maintainOutgoing();
    if (ret == 1) {
      _connected = true;
      _connectCompleter.complete(this);
    } else if (ret == 0) {
      _connectCompleter.completeError(DtlsException('handshake shut down'));
    } else {
      _handleError(ret, _connectCompleter.completeError);
    }
  }

  Future<_DtlsClientConnection> _connect({Duration? timeout}) {
    if (!_connectCompleter.isCompleted) {
      _connectToPeer();
    }

    final future = _connectCompleter.future;

    if (timeout != null) {
      return future.timeout(
        timeout,
        onTimeout: () async {
          await close();
          throw TimeoutException("Handshake timed out.");
        },
      );
    }

    return future;
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

    if (!closedByClient) {
      // This distinction is made to avoid concurrent modification errors.
      DtlsClient._connections.remove(_ssl.address);
      final connectionCacheKey = getConnectionKey(_address, _port);
      _dtlsClient._connectionCache.remove(connectionCacheKey);
    }

    final connected = _connected;

    if (connected) {
      _connected = false;
      _libSsl.SSL_shutdown(_ssl);
      _maintainState();
    }

    _libSsl.SSL_free(_ssl);

    _closed = true;
    _connected = false;

    if (connected) {
      await _received.close();
    }
  }

  void _incoming(Uint8List input) {
    buffer.asTypedList(bufferSize).setAll(0, input);
    _libCrypto.BIO_write(_rbio, buffer.cast(), input.length);
    _maintainState();
  }

  void _maintainOutgoing() {
    final ret = _libCrypto.BIO_read(_wbio, buffer.cast(), bufferSize);
    if (ret > 0) {
      _dtlsClient._socket.send(buffer.asTypedList(ret), _address, _port);
    }
    _timer?.cancel();
    if (_libSsl.SSL_ctrl(_ssl, DTLS_CTRL_GET_TIMEOUT, 0, buffer.cast()) > 0) {
      _timer = Timer(buffer.cast<timeval>().ref.duration, _maintainState);
    }
  }

  void _maintainState() {
    if (_connectCompleter.isCompleted) {
      final ret = _libSsl.SSL_read(_ssl, buffer.cast(), bufferSize);
      if (ret > 0) {
        final data = Uint8List.fromList(buffer.asTypedList(ret));
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
  })  : _pskCredentialsCallback = pskCredentialsCallback,
        _withTrustedRoots = withTrustedRoots,
        _verify = verify,
        _rootCertificates = rootCertificates,
        _ciphers = ciphers;

  final bool _withTrustedRoots;

  final bool _verify;

  final PskCredentialsCallback? _pskCredentialsCallback;

  final List<Uint8List> _rootCertificates;

  final String? _ciphers;

  void _addRoots(
    List<Uint8List> certs,
    Pointer<SSL_CTX> ctx,
    OpenSsl libSsl,
  ) {
    if (certs.isEmpty) return;
    final bufLen = certs.map((c) => c.length).reduce(max);
    final buf = malloc.call<UnsignedChar>(bufLen);
    final data = malloc.call<Pointer<UnsignedChar>>(1);
    final store = libSsl.SSL_CTX_get_cert_store(ctx);

    for (final cert in certs) {
      buf.cast<Uint8>().asTypedList(bufLen).setAll(0, cert);
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

  Pointer<SSL_CTX> _generateSslContext(OpenSsl libSsl) {
    final ctx = libSsl.SSL_CTX_new(libSsl.DTLS_client_method());

    if (_withTrustedRoots) {
      libSsl.SSL_CTX_set_default_verify_paths(ctx);
    }

    _addRoots(_rootCertificates, ctx, libSsl);
    libSsl.SSL_CTX_set_verify(
        ctx, _verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);

    final ciphers = _ciphers;
    if (ciphers != null) {
      final ciphersStr = ciphers.toNativeUtf8();
      libSsl.SSL_CTX_set_cipher_list(ctx, ciphersStr.cast());
      malloc.free(ciphersStr);
    }

    return ctx;
  }
}
