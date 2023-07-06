// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import "dart:async";
import "dart:ffi";
import "dart:io";
import "dart:math";
import "dart:typed_data";

import "package:dtls2/src/buffer.dart";
import "package:dtls2/src/dtls_alert.dart";
import "package:dtls2/src/dtls_connection.dart";
import "package:dtls2/src/dtls_exception.dart";
import "package:dtls2/src/generated/ffi.dart";
import "package:dtls2/src/lib.dart";
import "package:dtls2/src/psk_credentials.dart";
import "package:dtls2/src/util.dart";
import "package:ffi/ffi.dart";

const _pskErrorCode = 0;

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
  })  : _libCrypto = loadLibCrypto(libCrypto),
        _libSsl = loadLibSsl(libSsl) {
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
            final connection = _retrieveConnection(data.address, data.port);

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

  /// Closes this [DtlsClient].
  ///
  /// [RawDatagramSocket]s that have been passed in by the user are only closed
  /// if [closeExternalSocket] is set to `true`.
  Future<void> close({bool closeExternalSocket = false}) async {
    if (_closed) {
      return;
    }

    await _connectionCache.closeConnections();

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
    final existingConnection = _retrieveConnection(address, port);

    if (existingConnection == null) {
      return _DtlsClientConnection._connect(
        this,
        hostname,
        address,
        port,
        context._generateSslContext(_libSsl),
        context._pskCredentialsCallback,
        _libCrypto,
        _libSsl,
        timeout: timeout,
      );
    }

    if (!existingConnection.connected) {
      throw StateError(
        "Client connection to peer "
        "${existingConnection._address}:${existingConnection._port} "
        "has not been properly cleaned up.",
      );
    }

    return existingConnection;
  }

  int _send(_DtlsClientConnection dtlsClientConnection, List<int> data) {
    buffer.asTypedList(bufferSize).setAll(0, data);
    final ret = _libSsl.SSL_write(
      dtlsClientConnection._ssl,
      buffer.cast(),
      data.length,
    );
    dtlsClientConnection._maintainOutgoing();
    if (ret < 0) {
      dtlsClientConnection._handleError(
        ret,
        () {
          close();
          throw DtlsException("Sending data to peer has failed.");
        },
      );
    }
    return ret;
  }

  _DtlsClientConnection? _retrieveConnection(
    InternetAddress address,
    int port,
  ) {
    final key = getConnectionKey(address, port);
    return _connectionCache[key];
  }

  void _saveConnection(
    _DtlsClientConnection connection,
    InternetAddress address,
    int port,
  ) {
    final key = getConnectionKey(address, port);
    _connectionCache[key] = connection;
    DtlsClient._connections[connection._ssl.address] = connection;
  }

  void _removeConnection(InternetAddress address, int port) {
    final key = getConnectionKey(address, port);
    final removedConnection = _connectionCache.remove(key);

    if (removedConnection != null) {
      DtlsClient._connections.remove(removedConnection._ssl.address);
    }
  }
}

class _DtlsClientConnection extends Stream<Datagram> with DtlsConnection {
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
    this._connectCompleter,
  )   : _ssl = _libSsl.SSL_new(sslContext),
        _rbio = _libCrypto.BIO_new(_libCrypto.BIO_s_mem()),
        _wbio = _libCrypto.BIO_new(_libCrypto.BIO_s_mem()) {
    _setBios();
    _setInfoCallback(sslContext);
    _setHostname(hostname);
    _setPskCallback();
    _checkSslCiphers();
    _dtlsClient._saveConnection(this, _address, _port);
    _connectToPeer();
  }

  static Future<_DtlsClientConnection> _connect(
    DtlsClient dtlsClient,
    String? hostname,
    InternetAddress address,
    int port,
    Pointer<SSL_CTX> sslContext,
    PskCredentialsCallback? pskCredentialsCallback,
    OpenSsl libCrypto,
    OpenSsl libSsl, {
    Duration? timeout,
  }) {
    final connectCompleter = Completer<_DtlsClientConnection>();
    final connection = _DtlsClientConnection(
      dtlsClient,
      hostname,
      address,
      port,
      sslContext,
      pskCredentialsCallback,
      libCrypto,
      libSsl,
      connectCompleter,
    );

    final future = connectCompleter.future;

    if (timeout != null) {
      return future.timeout(
        timeout,
        onTimeout: () async {
          await connection.close();
          throw TimeoutException("Handshake timed out.");
        },
      );
    }

    return future;
  }

  final Pointer<SSL> _ssl;

  final InternetAddress _address;

  final int _port;

  final Completer<_DtlsClientConnection> _connectCompleter;

  final Pointer<BIO> _rbio;

  final Pointer<BIO> _wbio;

  final _received = StreamController<Datagram>();

  final PskCredentialsCallback? _pskCredentialsCallback;

  @override
  bool get connected => state == ConnectionState.connected;

  Timer? _timer;

  final OpenSsl _libSsl;

  final OpenSsl _libCrypto;

  @override
  ConnectionState state = ConnectionState.uninitialized;

  void _setBios() {
    _libSsl.SSL_set_bio(_ssl, _rbio, _wbio);
    _libCrypto
      ..BIO_ctrl(_rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr)
      ..BIO_ctrl(_wbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);
  }

  void _setInfoCallback(Pointer<SSL_CTX> sslContext) {
    _libSsl
      ..SSL_CTX_set_info_callback(
        sslContext,
        Pointer.fromFunction(_infoCallback),
      )
      ..SSL_CTX_free(sslContext);
  }

  void _setPskCallback() {
    if (_pskCredentialsCallback == null) {
      return;
    }

    final callback = Pointer.fromFunction<
        UnsignedInt Function(
          Pointer<SSL>,
          Pointer<Char>,
          Pointer<Char>,
          UnsignedInt,
          Pointer<UnsignedChar>,
          UnsignedInt,
        )>(_pskCallback, _pskErrorCode);

    _libSsl.SSL_set_psk_client_callback(_ssl, callback);
  }

  void _setHostname(String? hostname) {
    if (hostname == null) {
      return;
    }

    final hostnameStr = hostname.toNativeUtf8();
    _libCrypto.X509_VERIFY_PARAM_set1_host(
      _libSsl.SSL_get0_param(_ssl),
      hostnameStr.cast(),
      hostnameStr.length,
    );
    _libSsl.SSL_ctrl(
      _ssl,
      SSL_CTRL_SET_TLSEXT_HOSTNAME,
      TLSEXT_NAMETYPE_host_name,
      hostnameStr.cast(),
    );
    malloc.free(hostnameStr);
  }

  /// Throws a [DtlsException] if no ciphers are available for this connection
  /// attempt.
  ///
  /// If this is the case, the allocated resources are cleaned up by calling the
  /// [close] method.
  void _checkSslCiphers() {
    final ciphersPointer = _libSsl.SSL_get1_supported_ciphers(_ssl);

    if (ciphersPointer == nullptr) {
      close().then(
        (_) => throw DtlsException(
          "No ciphers available. "
          "If you are using PSK cipher suites, check you have defined a "
          "pskCredentialsCallback.",
        ),
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
    int maxPskLength,
  ) {
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

    if (connectionIdentity.length > maxIdentityLength ||
        connectionPsk.length > maxPskLength) {
      return _pskErrorCode;
    }

    identity
        .cast<Uint8>()
        .asTypedList(connectionIdentity.length)
        .setAll(0, connectionIdentity);
    psk
        .cast<Uint8>()
        .asTypedList(connectionPsk.length)
        .setAll(0, connectionPsk);
    return connectionPsk.length;
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

  void _handleError(int ret, void Function() errorHandler) {
    // TODO: Error code handling needs to be reworked.
    final code = _libSsl.SSL_get_error(_ssl, ret);
    switch (code) {
      case SSL_ERROR_SSL:
      case SSL_ERROR_SYSCALL:
        close();
        errorHandler();
        break;
      case SSL_ERROR_ZERO_RETURN:
        close();
    }
  }

  void _performShutdown(Exception exception) {
    final wasInHandshake = inHandshake;
    close();

    if (wasInHandshake) {
      _connectCompleter.completeError(exception);
    } else {
      throw exception;
    }
  }

  void _connectToPeer() {
    state = ConnectionState.handshake;
    final ret = _libSsl.SSL_connect(_ssl);
    final success = _maintainOutgoing();

    if (ret == 1) {
      state = ConnectionState.connected;
      _connectCompleter.complete(this);
    } else if (ret == 0) {
      _performShutdown(DtlsException("Handshake shut down"));
    } else {
      if (!success) {
        _performShutdown(const SocketException("Network is unreachable"));
        return;
      }

      _handleError(
        ret,
        () => _performShutdown(DtlsHandshakeException("DTLS Handshake has failed.")),
      );
    }
  }

  @override
  int send(List<int> data) {
    if (!connected) {
      throw DtlsException("Sending failed: Not connected!");
    }

    return _dtlsClient._send(this, data);
  }

  /// Closes the connection and frees all allocated resources.
  ///
  /// After the connection is closed, trying to send will throw a
  /// [DtlsException].
  @override
  Future<void> close() async {
    if (!state.canBeClosed) {
      return;
    }

    final wasConnected = connected;

    state = ConnectionState.closing;

    _timer?.cancel();

    _dtlsClient._removeConnection(_address, _port);

    if (wasConnected) {
      _libSsl.SSL_shutdown(_ssl);
      _maintainState();
      await _received.close();
    }

    _libSsl.SSL_free(_ssl);
    state = ConnectionState.closed;
  }

  void _incoming(Uint8List input) {
    buffer.asTypedList(bufferSize).setAll(0, input);
    _libCrypto.BIO_write(_rbio, buffer.cast(), input.length);
    _maintainState();
  }

  bool _maintainOutgoing() {
    final ret = _libCrypto.BIO_read(_wbio, buffer.cast(), bufferSize);

    if (ret > 0) {
      final bytesSent =
          _dtlsClient._socket.send(buffer.asTypedList(ret), _address, _port);

      if (bytesSent <= 0) {
        return false;
      }
    }

    _timer?.cancel();
    if (_libSsl.SSL_ctrl(_ssl, DTLS_CTRL_GET_TIMEOUT, 0, buffer.cast()) > 0) {
      _timer = Timer(buffer.cast<timeval>().ref.duration, _maintainState);
    }

    return true;
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
        _handleError(
          ret,
          () => _received.addError(DtlsException("An error has occured.")),
        );
      }
    } else {
      _connectToPeer();
    }
  }

  @override
  StreamSubscription<Datagram> listen(
    void Function(Datagram event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _received.stream.listen(
        onData,
        onError: onError,
        onDone: onDone,
        cancelOnError: cancelOnError,
      );
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
    final data = malloc.call<Pointer<UnsignedChar>>();
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
      ctx,
      _verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
      nullptr,
    );

    final ciphers = _ciphers;
    if (ciphers != null) {
      final ciphersStr = ciphers.toNativeUtf8();
      libSsl.SSL_CTX_set_cipher_list(ctx, ciphersStr.cast());
      malloc.free(ciphersStr);
    }

    return ctx;
  }
}
