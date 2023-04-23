// Copyright (c) 2023 Jan Romann
// SPDX-License-Identifier: MIT

import "dart:async";
import "dart:convert";
import "dart:ffi";
import "dart:io";
import "dart:math";
import "dart:typed_data";

import "package:collection/collection.dart";
import "package:dtls2/src/buffer.dart";
import "package:dtls2/src/dtls_alert.dart";
import "package:dtls2/src/dtls_connection.dart";
import "package:dtls2/src/dtls_exception.dart";
import "package:dtls2/src/generated/ffi.dart";
import "package:dtls2/src/lib.dart";
import "package:dtls2/src/util.dart";
import "package:ffi/ffi.dart";

/// Callback signature for retrieving Pre-Shared Keys from a [DtlsServer]'s
/// keystore.
typedef PskKeyStoreCallback = Iterable<int>? Function(List<int> identity);

/// Provides DTLS server functionality based on OpenSSL.
///
/// Allows you to [bind] the [DtlsServer] to a UDP port of your choice. Once a
/// connection to a client is established, the server emits
/// [DtlsConnection]s you can [listen] for.
class DtlsServer extends Stream<DtlsConnection> {
  /// Constructor
  DtlsServer(
    this._socket,
    this._context, {
    DynamicLibrary? libSsl,
    DynamicLibrary? libCrypto,
  })  : _sslContext = _context._generateSslContext(loadLibSsl(libSsl)),
        _libCrypto = loadLibCrypto(libCrypto),
        _libSsl = loadLibSsl(libSsl) {
    _setCallbacks();
    _startListening();
  }

  bool _closed = false;

  bool _externalSocket = true;

  final DtlsServerContext _context;

  final RawDatagramSocket _socket;

  final Pointer<SSL_CTX> _sslContext;

  final OpenSsl _libSsl;

  final OpenSsl _libCrypto;

  final _connectionStream = StreamController<_DtlsServerConnection>();

  Stream<_DtlsServerConnection> get _receivedStream => _connectionStream.stream;

  /// Maps combinations of [InternetAddress]es and ports to
  /// [_DtlsServerConnection]s to enable caching for this client.
  final Map<String, _DtlsServerConnection> _connectionCache = {};

  /// Maps OpenSSL sessions to [_DtlsServerConnection]s.
  static final Map<int, _DtlsServerConnection> _connections = {};

  /// Binds a [DtlsServer] to the given [host] and [port], using the security
  /// parameters defined in the [context].
  ///
  /// Uses a [RawDatagramSocket] internally and passes the [host], [port],
  /// and [ttl] arguments to it.
  static Future<DtlsServer> bind(
    dynamic host,
    int port,
    DtlsServerContext context, {
    int ttl = 1,
    DynamicLibrary? libCrypto,
    DynamicLibrary? libSsl,
  }) async {
    final socket = await RawDatagramSocket.bind(host, port, ttl: ttl);
    return DtlsServer(
      socket,
      context,
      libCrypto: libCrypto,
      libSsl: libSsl,
    ).._externalSocket = false;
  }

  void _handleSocketRead() {
    final datagram = _socket.receive();
    if (datagram == null) {
      return;
    }

    final connection = _retrieveConnection(datagram.address, datagram.port) ??
        _establishConnection(datagram);

    connection?._incoming(datagram.data);
  }

  _DtlsServerConnection? _establishConnection(Datagram datagram) {
    // TODO(JKRhb): Check if there is a better way to assert this.
    if (!datagram.data.isValidClientHello()) {
      return null;
    }

    return _DtlsServerConnection(
      this,
      datagram.address,
      datagram.port,
      _sslContext,
      _libCrypto,
      _libSsl,
    );
  }

  void _startListening() {
    _socket.listen((event) async {
      switch (event) {
        case RawSocketEvent.read:
          _handleSocketRead();
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

  @override
  StreamSubscription<DtlsConnection> listen(
    void Function(DtlsConnection event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _receivedStream.listen(
        onData,
        onError: onError,
        onDone: onDone,
        cancelOnError: cancelOnError,
      );

  int _send(_DtlsServerConnection dtlsServerConnection, List<int> data) {
    buffer.asTypedList(bufferSize).setAll(0, data);
    final ret = _libSsl.SSL_write(
      dtlsServerConnection._ssl,
      buffer.cast(),
      data.length,
    );
    dtlsServerConnection._maintainOutgoing();
    if (ret < 0) {
      dtlsServerConnection._handleError(ret, (e) => throw e);
    }
    return ret;
  }

  /// Closes this [DtlsServer].
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

    _libSsl.SSL_CTX_free(_sslContext);

    await _connectionStream.close();
    _closed = true;
  }

  void _setCallbacks() {
    const error = -1;

    _libSsl
      ..SSL_CTX_set_cookie_generate_cb(
        _sslContext,
        Pointer.fromFunction(_dtlsCookieGenerateCallback, error),
      )
      ..SSL_CTX_set_cookie_verify_cb(
        _sslContext,
        Pointer.fromFunction(_dtlsCookieVerifyCallback, error),
      )
      ..SSL_CTX_set_info_callback(
        _sslContext,
        Pointer.fromFunction(_infoCallback),
      );
  }

  _DtlsServerConnection? _retrieveConnection(
    InternetAddress address,
    int port,
  ) {
    final key = getConnectionKey(address, port);
    return _connectionCache[key];
  }

  void _saveConnection(
    _DtlsServerConnection connection,
    InternetAddress address,
    int port,
  ) {
    final key = getConnectionKey(address, port);
    _connectionCache[key] = connection;
    DtlsServer._connections[connection._ssl.address] = connection;
  }

  void _removeConnection(InternetAddress address, int port) {
    final key = getConnectionKey(address, port);
    final removedConnection = _connectionCache.remove(key);

    if (removedConnection != null) {
      DtlsServer._connections.remove(removedConnection._ssl.address);
    }
  }
}

/// This Event is emitted if a [DtlsServer] receives application data.
class _DtlsServerConnection extends Stream<Datagram> with DtlsConnection {
  /// Create a [_DtlsServerConnection] using a [DtlsServerContext].
  _DtlsServerConnection(
    this._dtlsServer,
    this._address,
    this._port,
    Pointer<SSL_CTX> _sslContext,
    this._libCrypto,
    this._libSsl,
  )   : _rbio = _libCrypto.BIO_new(_libCrypto.BIO_s_mem()),
        _wbio = _libCrypto.BIO_new(_libCrypto.BIO_s_mem()),
        _bioAddr = _libCrypto.BIO_ADDR_new(),
        _ssl = _libSsl.SSL_new(_sslContext) {
    _libSsl.SSL_set_bio(_ssl, _rbio, _wbio);
    _libCrypto
      ..BIO_ctrl(_rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr)
      ..BIO_ctrl(_wbio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, nullptr);

    _dtlsServer._saveConnection(this, _address, _port);
  }

  final DtlsServer _dtlsServer;

  final InternetAddress _address;

  final int _port;

  final Pointer<SSL> _ssl;

  final Pointer<BIO> _rbio;

  final Pointer<BIO> _wbio;

  final _received = StreamController<Datagram>();

  final cookie = _generateCookie();

  @override
  ConnectionState state = ConnectionState.uninitialized;

  @override
  bool get connected => state == ConnectionState.connected;

  Timer? _timer;

  final OpenSsl _libSsl;

  final OpenSsl _libCrypto;

  void _performShutdown([Exception? exception]) {
    state = ConnectionState.closed;
    close();

    if (exception != null) {
      throw exception;
    }
  }

  static List<int> _generateCookie() {
    const cookieLength = 32;
    final random = Random();
    return List<int>.generate(cookieLength, (i) => random.nextInt(256));
  }

  void _maintainState() {
    if (state == ConnectionState.uninitialized) {
      _connectToPeer();
      return;
    }

    final ret = _libSsl.SSL_read(_ssl, buffer.cast(), bufferSize);

    if (ret > 0) {
      if (state == ConnectionState.handshake) {
        final acceptValue = _libSsl.SSL_accept(_ssl);

        if (acceptValue == 1) {
          state = ConnectionState.connected;
        } else {
          _performShutdown();
          return;
        }
      }

      final data = Uint8List.fromList(buffer.asTypedList(ret));
      final datagram = Datagram(data, _address, _port);
      _received.add(datagram);
      _maintainOutgoing();
    } else {
      _maintainOutgoing();
      _handleError(ret);
    }
  }

  final Pointer<bio_addr_st> _bioAddr;

  void _connectToPeer() {
    final ret = _libSsl.DTLSv1_listen(_ssl, _bioAddr);
    _maintainOutgoing();
    if (ret == 1) {
      state = ConnectionState.handshake;
      _dtlsServer._connectionStream.add(this);
    } else {
      _handleError(ret);
    }
  }

  void _maintainOutgoing() {
    final ret = _libCrypto.BIO_read(_wbio, buffer.cast(), bufferSize);
    if (ret > 0) {
      final bytesSent =
          _dtlsServer._socket.send(buffer.asTypedList(ret), _address, _port);

      if (bytesSent <= 0) {
        _performShutdown(const SocketException("Network unreachable."));
      }
    }
    _timer?.cancel();
    if (_libSsl.SSL_ctrl(_ssl, DTLS_CTRL_GET_TIMEOUT, 0, buffer.cast()) > 0) {
      _timer = Timer(buffer.cast<timeval>().ref.duration, _maintainState);
    }
  }

  void _incoming(Uint8List input) {
    buffer.asTypedList(bufferSize).setAll(0, input);
    _libCrypto.BIO_write(_rbio, buffer.cast(), input.length);
    _maintainState();
  }

  @override
  Future<void> close() async {
    if (!state.canBeClosed) {
      return;
    }

    final wasConnected = connected;
    state = ConnectionState.closing;

    _timer?.cancel();
    _dtlsServer._removeConnection(_address, _port);

    if (wasConnected) {
      _libSsl.SSL_shutdown(_ssl);
      _maintainState();
      await _received.close();
    }

    _libSsl.SSL_free(_ssl);
    _libCrypto.BIO_ADDR_free(_bioAddr);
    state = ConnectionState.closed;
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

  @override
  int send(List<int> data) {
    if (state != ConnectionState.connected) {
      throw DtlsException("Sending failed: Not connected!");
    }

    return _dtlsServer._send(this, data);
  }

  void _handleError(int ret, [void Function(Exception)? errorHandler]) {
    final code = _libSsl.SSL_get_error(_ssl, ret);
    if (code == SSL_ERROR_SSL) {
      errorHandler?.call(
        DtlsException(
          _libCrypto.ERR_error_string(_libCrypto.ERR_get_error(), nullptr)
              .cast<Utf8>()
              .toDartString(),
        ),
      );
    } else if (code == SSL_ERROR_ZERO_RETURN) {
      close();
    }
  }

  void _handleDtlsEvent(DtlsAlert event) {
    if (event.requiresClosing) {
      close();
    }
  }
}

/// The context contains settings for DTLS session establishment.
///
/// Wrapper for `SSL_CTX`.
class DtlsServerContext {
  /// [verify] enables certificate verification (recommended).
  ///
  /// To allow the verification to succeed, system certificates have to be
  /// imported using [withTrustedRoots], or custom root certificates
  /// in DER format need to be imported with [rootCertificates].
  /// System certificates are available only when OpenSSL is installed by
  /// the system.
  ///
  /// [ciphers] controls the cipher suites offered to the server.
  DtlsServerContext({
    bool verify = true,
    bool withTrustedRoots = false,
    List<Uint8List> rootCertificates = const [],
    String? ciphers,
    PskKeyStoreCallback? pskKeyStoreCallback,
    String? identityHint,
  })  : _pskKeyStoreCallback = pskKeyStoreCallback,
        _withTrustedRoots = withTrustedRoots,
        _verify = verify,
        _rootCertificates = rootCertificates,
        _ciphers = ciphers,
        _identityHint = identityHint;

  final bool _withTrustedRoots;

  final bool _verify;

  final PskKeyStoreCallback? _pskKeyStoreCallback;

  final List<Uint8List> _rootCertificates;

  final String? _ciphers;

  final String? _identityHint;

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
    final ctx = libSsl.SSL_CTX_new(libSsl.DTLS_server_method());

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

    if (_pskKeyStoreCallback != null) {
      const error = -1;
      final callback = Pointer.fromFunction<
          UnsignedInt Function(
        Pointer<SSL>,
        Pointer<Char>,
        Pointer<UnsignedChar>,
        UnsignedInt,
      )>(_pskCallback, error);

      libSsl.SSL_CTX_set_psk_server_callback(ctx, callback);
    }

    final identityHint = _identityHint;
    if (identityHint != null) {
      final nativeIdentityHint = identityHint.toNativeUtf8();
      libSsl.SSL_CTX_use_psk_identity_hint(ctx, nativeIdentityHint.cast());
      malloc.free(nativeIdentityHint);
    }

    return ctx;
  }
}

int _pskCallback(
  Pointer<SSL> ssl,
  Pointer<Char> identity,
  Pointer<UnsignedChar> psk,
  int maxPskLength,
) {
  final connection = _getServerConnection(ssl);

  final identityString = identity.cast<Utf8>().toDartString();
  final identityBytes = Uint8List.fromList(utf8.encode(identityString));

  final pskCredentials =
      connection._dtlsServer._context._pskKeyStoreCallback?.call(identityBytes);

  if (pskCredentials == null) {
    return 0;
  }

  final pskLength = pskCredentials.length;

  psk.cast<Uint8>().asTypedList(pskLength).setAll(0, pskCredentials);
  return pskLength;
}

_DtlsServerConnection _getServerConnection(Pointer<SSL> ssl) {
  final connection = DtlsServer._connections[ssl.address];

  if (connection == null) {
    throw StateError("No DTLS Connection found for SSL object!");
  }

  return connection;
}

void _infoCallback(
  Pointer<SSL> ssl,
  int where,
  int ret,
) {
  if (!where.isAlert) {
    return;
  }

  final connection = _getServerConnection(ssl);

  final event = DtlsAlert.fromCode(ret);

  if (event != null) {
    connection._handleDtlsEvent(event);
  }
}

extension _IntToBytes on int {
  Uint8List toUint8List() => Uint8List(8)..buffer.asUint64List()[0] = this;
}

/// Callback function for generating a DTLS server callback.
int _dtlsCookieGenerateCallback(
  Pointer<SSL> ssl,
  Pointer<UnsignedChar> cookie,
  Pointer<UnsignedInt> cookieLength,
) {
  final testCookie = Uint8List.fromList(_getServerConnection(ssl).cookie);

  cookie
      .cast<Uint8>()
      .asTypedList(testCookie.lengthInBytes)
      .setAll(0, testCookie);

  final lengthBytes = testCookie.lengthInBytes.toUint8List();

  cookieLength
      .cast<Uint8>()
      .asTypedList(lengthBytes.length)
      .setAll(0, lengthBytes);

  return testCookie.lengthInBytes;
}

/// Callback function for generating cookies from re-sent Client Hellos.
int _dtlsCookieVerifyCallback(
  Pointer<SSL> ssl,
  Pointer<UnsignedChar> cookie,
  int cookieLength,
) {
  final connection = _getServerConnection(ssl);
  final connectionCookie = Uint8List.fromList(connection.cookie);

  final peerCookie = cookie.cast<Uint8>().asTypedList(cookieLength);

  return const ListEquality<int>().equals(connectionCookie, peerCookie) ? 1 : 0;
}

extension _ClintHelloParseExtension on Uint8List {
  bool isValidClientHello() {
    var valid = true;

    var index = 0;

    valid = valid && this[index] == 22;
    index++;

    valid = valid && this[index] == 254;
    index++;

    valid = valid && const [255, 253].contains(this[index]);
    index++;

    const epochLength = 2;
    const sequenceNumberLength = 6;
    const lengthFieldLength = 2;

    index = index + epochLength + sequenceNumberLength + lengthFieldLength;

    const clientHelloCode = 1;

    return valid && this[index] == clientHelloCode;
  }
}
