// ignore_for_file: camel_case_types, non_constant_identifier_names
// ignore_for_file: constant_identifier_names, public_member_api_docs
// ignore_for_file: unused_field, lines_longer_than_80_chars

// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
// ignore_for_file: type=lint
import 'dart:ffi' as ffi;

/// Bindings to OpenSSL for DTLS support in Dart.
class OpenSsl {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  OpenSsl(ffi.DynamicLibrary dynamicLibrary) : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  OpenSsl.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  int OPENSSL_version_major() {
    return _OPENSSL_version_major();
  }

  late final _OPENSSL_version_majorPtr =
      _lookup<ffi.NativeFunction<ffi.UnsignedInt Function()>>(
          'OPENSSL_version_major');
  late final _OPENSSL_version_major =
      _OPENSSL_version_majorPtr.asFunction<int Function()>();

  int OPENSSL_version_minor() {
    return _OPENSSL_version_minor();
  }

  late final _OPENSSL_version_minorPtr =
      _lookup<ffi.NativeFunction<ffi.UnsignedInt Function()>>(
          'OPENSSL_version_minor');
  late final _OPENSSL_version_minor =
      _OPENSSL_version_minorPtr.asFunction<int Function()>();

  int OPENSSL_version_patch() {
    return _OPENSSL_version_patch();
  }

  late final _OPENSSL_version_patchPtr =
      _lookup<ffi.NativeFunction<ffi.UnsignedInt Function()>>(
          'OPENSSL_version_patch');
  late final _OPENSSL_version_patch =
      _OPENSSL_version_patchPtr.asFunction<int Function()>();

  ffi.Pointer<BIO> BIO_new(
    ffi.Pointer<BIO_METHOD> type,
  ) {
    return _BIO_new(
      type,
    );
  }

  late final _BIO_newPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<BIO> Function(ffi.Pointer<BIO_METHOD>)>>('BIO_new');
  late final _BIO_new = _BIO_newPtr.asFunction<
      ffi.Pointer<BIO> Function(ffi.Pointer<BIO_METHOD>)>();

  int BIO_free(
    ffi.Pointer<BIO> a,
  ) {
    return _BIO_free(
      a,
    );
  }

  late final _BIO_freePtr =
      _lookup<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<BIO>)>>(
          'BIO_free');
  late final _BIO_free =
      _BIO_freePtr.asFunction<int Function(ffi.Pointer<BIO>)>();

  int BIO_read(
    ffi.Pointer<BIO> b,
    ffi.Pointer<ffi.Void> data,
    int dlen,
  ) {
    return _BIO_read(
      b,
      data,
      dlen,
    );
  }

  late final _BIO_readPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(
              ffi.Pointer<BIO>, ffi.Pointer<ffi.Void>, ffi.Int)>>('BIO_read');
  late final _BIO_read = _BIO_readPtr.asFunction<
      int Function(ffi.Pointer<BIO>, ffi.Pointer<ffi.Void>, int)>();

  int BIO_write(
    ffi.Pointer<BIO> b,
    ffi.Pointer<ffi.Void> data,
    int dlen,
  ) {
    return _BIO_write(
      b,
      data,
      dlen,
    );
  }

  late final _BIO_writePtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(
              ffi.Pointer<BIO>, ffi.Pointer<ffi.Void>, ffi.Int)>>('BIO_write');
  late final _BIO_write = _BIO_writePtr.asFunction<
      int Function(ffi.Pointer<BIO>, ffi.Pointer<ffi.Void>, int)>();

  int BIO_ctrl(
    ffi.Pointer<BIO> bp,
    int cmd,
    int larg,
    ffi.Pointer<ffi.Void> parg,
  ) {
    return _BIO_ctrl(
      bp,
      cmd,
      larg,
      parg,
    );
  }

  late final _BIO_ctrlPtr = _lookup<
      ffi.NativeFunction<
          ffi.Long Function(ffi.Pointer<BIO>, ffi.Int, ffi.Long,
              ffi.Pointer<ffi.Void>)>>('BIO_ctrl');
  late final _BIO_ctrl = _BIO_ctrlPtr.asFunction<
      int Function(ffi.Pointer<BIO>, int, int, ffi.Pointer<ffi.Void>)>();

  ffi.Pointer<BIO_METHOD> BIO_s_mem() {
    return _BIO_s_mem();
  }

  late final _BIO_s_memPtr =
      _lookup<ffi.NativeFunction<ffi.Pointer<BIO_METHOD> Function()>>(
          'BIO_s_mem');
  late final _BIO_s_mem =
      _BIO_s_memPtr.asFunction<ffi.Pointer<BIO_METHOD> Function()>();

  ffi.Pointer<BIO_METHOD> BIO_s_dgram_mem() {
    return _BIO_s_dgram_mem();
  }

  late final _BIO_s_dgram_memPtr =
      _lookup<ffi.NativeFunction<ffi.Pointer<BIO_METHOD> Function()>>(
          'BIO_s_dgram_mem');
  late final _BIO_s_dgram_mem =
      _BIO_s_dgram_memPtr.asFunction<ffi.Pointer<BIO_METHOD> Function()>();

  ffi.Pointer<BIO_ADDR> BIO_ADDR_new() {
    return _BIO_ADDR_new();
  }

  late final _BIO_ADDR_newPtr =
      _lookup<ffi.NativeFunction<ffi.Pointer<BIO_ADDR> Function()>>(
          'BIO_ADDR_new');
  late final _BIO_ADDR_new =
      _BIO_ADDR_newPtr.asFunction<ffi.Pointer<BIO_ADDR> Function()>();

  void BIO_ADDR_free(
    ffi.Pointer<BIO_ADDR> arg0,
  ) {
    return _BIO_ADDR_free(
      arg0,
    );
  }

  late final _BIO_ADDR_freePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<BIO_ADDR>)>>(
          'BIO_ADDR_free');
  late final _BIO_ADDR_free =
      _BIO_ADDR_freePtr.asFunction<void Function(ffi.Pointer<BIO_ADDR>)>();

  int X509_STORE_add_cert(
    ffi.Pointer<X509_STORE> xs,
    ffi.Pointer<X509> x,
  ) {
    return _X509_STORE_add_cert(
      xs,
      x,
    );
  }

  late final _X509_STORE_add_certPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(ffi.Pointer<X509_STORE>,
              ffi.Pointer<X509>)>>('X509_STORE_add_cert');
  late final _X509_STORE_add_cert = _X509_STORE_add_certPtr.asFunction<
      int Function(ffi.Pointer<X509_STORE>, ffi.Pointer<X509>)>();

  int X509_VERIFY_PARAM_set1_host(
    ffi.Pointer<X509_VERIFY_PARAM> param,
    ffi.Pointer<ffi.Char> name,
    int namelen,
  ) {
    return _X509_VERIFY_PARAM_set1_host(
      param,
      name,
      namelen,
    );
  }

  late final _X509_VERIFY_PARAM_set1_hostPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(ffi.Pointer<X509_VERIFY_PARAM>,
              ffi.Pointer<ffi.Char>, ffi.Size)>>('X509_VERIFY_PARAM_set1_host');
  late final _X509_VERIFY_PARAM_set1_host =
      _X509_VERIFY_PARAM_set1_hostPtr.asFunction<
          int Function(
              ffi.Pointer<X509_VERIFY_PARAM>, ffi.Pointer<ffi.Char>, int)>();

  void X509_free(
    ffi.Pointer<X509> a,
  ) {
    return _X509_free(
      a,
    );
  }

  late final _X509_freePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<X509>)>>(
          'X509_free');
  late final _X509_free =
      _X509_freePtr.asFunction<void Function(ffi.Pointer<X509>)>();

  ffi.Pointer<X509> d2i_X509(
    ffi.Pointer<ffi.Pointer<X509>> a,
    ffi.Pointer<ffi.Pointer<ffi.UnsignedChar>> in1,
    int len,
  ) {
    return _d2i_X509(
      a,
      in1,
      len,
    );
  }

  late final _d2i_X509Ptr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<X509> Function(
              ffi.Pointer<ffi.Pointer<X509>>,
              ffi.Pointer<ffi.Pointer<ffi.UnsignedChar>>,
              ffi.Long)>>('d2i_X509');
  late final _d2i_X509 = _d2i_X509Ptr.asFunction<
      ffi.Pointer<X509> Function(ffi.Pointer<ffi.Pointer<X509>>,
          ffi.Pointer<ffi.Pointer<ffi.UnsignedChar>>, int)>();

  void SSL_CTX_set_info_callback(
    ffi.Pointer<SSL_CTX> ctx,
    ffi.Pointer<
            ffi.NativeFunction<
                ffi.Void Function(
                    ffi.Pointer<SSL> ssl, ffi.Int type, ffi.Int val)>>
        cb,
  ) {
    return _SSL_CTX_set_info_callback(
      ctx,
      cb,
    );
  }

  late final _SSL_CTX_set_info_callbackPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(
              ffi.Pointer<SSL_CTX>,
              ffi.Pointer<
                  ffi.NativeFunction<
                      ffi.Void Function(ffi.Pointer<SSL> ssl, ffi.Int type,
                          ffi.Int val)>>)>>('SSL_CTX_set_info_callback');
  late final _SSL_CTX_set_info_callback =
      _SSL_CTX_set_info_callbackPtr.asFunction<
          void Function(
              ffi.Pointer<SSL_CTX>,
              ffi.Pointer<
                  ffi.NativeFunction<
                      ffi.Void Function(ffi.Pointer<SSL> ssl, ffi.Int type,
                          ffi.Int val)>>)>();

  void SSL_CTX_set_cookie_generate_cb(
    ffi.Pointer<SSL_CTX> ctx,
    ffi.Pointer<
            ffi.NativeFunction<
                ffi.Int Function(
                    ffi.Pointer<SSL> ssl,
                    ffi.Pointer<ffi.UnsignedChar> cookie,
                    ffi.Pointer<ffi.UnsignedInt> cookie_len)>>
        app_gen_cookie_cb,
  ) {
    return _SSL_CTX_set_cookie_generate_cb(
      ctx,
      app_gen_cookie_cb,
    );
  }

  late final _SSL_CTX_set_cookie_generate_cbPtr = _lookup<
          ffi.NativeFunction<
              ffi.Void Function(
                  ffi.Pointer<SSL_CTX>,
                  ffi.Pointer<
                      ffi.NativeFunction<
                          ffi.Int Function(
                              ffi.Pointer<SSL> ssl,
                              ffi.Pointer<ffi.UnsignedChar> cookie,
                              ffi.Pointer<ffi.UnsignedInt> cookie_len)>>)>>(
      'SSL_CTX_set_cookie_generate_cb');
  late final _SSL_CTX_set_cookie_generate_cb =
      _SSL_CTX_set_cookie_generate_cbPtr.asFunction<
          void Function(
              ffi.Pointer<SSL_CTX>,
              ffi.Pointer<
                  ffi.NativeFunction<
                      ffi.Int Function(
                          ffi.Pointer<SSL> ssl,
                          ffi.Pointer<ffi.UnsignedChar> cookie,
                          ffi.Pointer<ffi.UnsignedInt> cookie_len)>>)>();

  void SSL_CTX_set_cookie_verify_cb(
    ffi.Pointer<SSL_CTX> ctx,
    ffi.Pointer<
            ffi.NativeFunction<
                ffi.Int Function(
                    ffi.Pointer<SSL> ssl,
                    ffi.Pointer<ffi.UnsignedChar> cookie,
                    ffi.UnsignedInt cookie_len)>>
        app_verify_cookie_cb,
  ) {
    return _SSL_CTX_set_cookie_verify_cb(
      ctx,
      app_verify_cookie_cb,
    );
  }

  late final _SSL_CTX_set_cookie_verify_cbPtr = _lookup<
          ffi.NativeFunction<
              ffi.Void Function(
                  ffi.Pointer<SSL_CTX>,
                  ffi.Pointer<
                      ffi.NativeFunction<
                          ffi.Int Function(
                              ffi.Pointer<SSL> ssl,
                              ffi.Pointer<ffi.UnsignedChar> cookie,
                              ffi.UnsignedInt cookie_len)>>)>>(
      'SSL_CTX_set_cookie_verify_cb');
  late final _SSL_CTX_set_cookie_verify_cb =
      _SSL_CTX_set_cookie_verify_cbPtr.asFunction<
          void Function(
              ffi.Pointer<SSL_CTX>,
              ffi.Pointer<
                  ffi.NativeFunction<
                      ffi.Int Function(
                          ffi.Pointer<SSL> ssl,
                          ffi.Pointer<ffi.UnsignedChar> cookie,
                          ffi.UnsignedInt cookie_len)>>)>();

  void SSL_set_psk_client_callback(
    ffi.Pointer<SSL> ssl,
    SSL_psk_client_cb_func cb,
  ) {
    return _SSL_set_psk_client_callback(
      ssl,
      cb,
    );
  }

  late final _SSL_set_psk_client_callbackPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<SSL>,
              SSL_psk_client_cb_func)>>('SSL_set_psk_client_callback');
  late final _SSL_set_psk_client_callback = _SSL_set_psk_client_callbackPtr
      .asFunction<void Function(ffi.Pointer<SSL>, SSL_psk_client_cb_func)>();

  void SSL_CTX_set_psk_server_callback(
    ffi.Pointer<SSL_CTX> ctx,
    SSL_psk_server_cb_func cb,
  ) {
    return _SSL_CTX_set_psk_server_callback(
      ctx,
      cb,
    );
  }

  late final _SSL_CTX_set_psk_server_callbackPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<SSL_CTX>,
              SSL_psk_server_cb_func)>>('SSL_CTX_set_psk_server_callback');
  late final _SSL_CTX_set_psk_server_callback =
      _SSL_CTX_set_psk_server_callbackPtr.asFunction<
          void Function(ffi.Pointer<SSL_CTX>, SSL_psk_server_cb_func)>();

  int SSL_CTX_use_psk_identity_hint(
    ffi.Pointer<SSL_CTX> ctx,
    ffi.Pointer<ffi.Char> identity_hint,
  ) {
    return _SSL_CTX_use_psk_identity_hint(
      ctx,
      identity_hint,
    );
  }

  late final _SSL_CTX_use_psk_identity_hintPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(ffi.Pointer<SSL_CTX>,
              ffi.Pointer<ffi.Char>)>>('SSL_CTX_use_psk_identity_hint');
  late final _SSL_CTX_use_psk_identity_hint = _SSL_CTX_use_psk_identity_hintPtr
      .asFunction<int Function(ffi.Pointer<SSL_CTX>, ffi.Pointer<ffi.Char>)>();

  int SSL_CTX_set_cipher_list(
    ffi.Pointer<SSL_CTX> arg0,
    ffi.Pointer<ffi.Char> str,
  ) {
    return _SSL_CTX_set_cipher_list(
      arg0,
      str,
    );
  }

  late final _SSL_CTX_set_cipher_listPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(ffi.Pointer<SSL_CTX>,
              ffi.Pointer<ffi.Char>)>>('SSL_CTX_set_cipher_list');
  late final _SSL_CTX_set_cipher_list = _SSL_CTX_set_cipher_listPtr.asFunction<
      int Function(ffi.Pointer<SSL_CTX>, ffi.Pointer<ffi.Char>)>();

  ffi.Pointer<SSL_CTX> SSL_CTX_new(
    ffi.Pointer<SSL_METHOD> meth,
  ) {
    return _SSL_CTX_new(
      meth,
    );
  }

  late final _SSL_CTX_newPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<SSL_CTX> Function(
              ffi.Pointer<SSL_METHOD>)>>('SSL_CTX_new');
  late final _SSL_CTX_new = _SSL_CTX_newPtr.asFunction<
      ffi.Pointer<SSL_CTX> Function(ffi.Pointer<SSL_METHOD>)>();

  void SSL_CTX_free(
    ffi.Pointer<SSL_CTX> arg0,
  ) {
    return _SSL_CTX_free(
      arg0,
    );
  }

  late final _SSL_CTX_freePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<SSL_CTX>)>>(
          'SSL_CTX_free');
  late final _SSL_CTX_free =
      _SSL_CTX_freePtr.asFunction<void Function(ffi.Pointer<SSL_CTX>)>();

  ffi.Pointer<X509_STORE> SSL_CTX_get_cert_store(
    ffi.Pointer<SSL_CTX> arg0,
  ) {
    return _SSL_CTX_get_cert_store(
      arg0,
    );
  }

  late final _SSL_CTX_get_cert_storePtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<X509_STORE> Function(
              ffi.Pointer<SSL_CTX>)>>('SSL_CTX_get_cert_store');
  late final _SSL_CTX_get_cert_store = _SSL_CTX_get_cert_storePtr.asFunction<
      ffi.Pointer<X509_STORE> Function(ffi.Pointer<SSL_CTX>)>();

  void SSL_set_bio(
    ffi.Pointer<SSL> s,
    ffi.Pointer<BIO> rbio,
    ffi.Pointer<BIO> wbio,
  ) {
    return _SSL_set_bio(
      s,
      rbio,
      wbio,
    );
  }

  late final _SSL_set_bioPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<SSL>, ffi.Pointer<BIO>,
              ffi.Pointer<BIO>)>>('SSL_set_bio');
  late final _SSL_set_bio = _SSL_set_bioPtr.asFunction<
      void Function(ffi.Pointer<SSL>, ffi.Pointer<BIO>, ffi.Pointer<BIO>)>();

  void SSL_CTX_set_verify(
    ffi.Pointer<SSL_CTX> ctx,
    int mode,
    SSL_verify_cb callback,
  ) {
    return _SSL_CTX_set_verify(
      ctx,
      mode,
      callback,
    );
  }

  late final _SSL_CTX_set_verifyPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<SSL_CTX>, ffi.Int,
              SSL_verify_cb)>>('SSL_CTX_set_verify');
  late final _SSL_CTX_set_verify = _SSL_CTX_set_verifyPtr.asFunction<
      void Function(ffi.Pointer<SSL_CTX>, int, SSL_verify_cb)>();

  ffi.Pointer<SSL> SSL_new(
    ffi.Pointer<SSL_CTX> ctx,
  ) {
    return _SSL_new(
      ctx,
    );
  }

  late final _SSL_newPtr = _lookup<
          ffi.NativeFunction<ffi.Pointer<SSL> Function(ffi.Pointer<SSL_CTX>)>>(
      'SSL_new');
  late final _SSL_new =
      _SSL_newPtr.asFunction<ffi.Pointer<SSL> Function(ffi.Pointer<SSL_CTX>)>();

  ffi.Pointer<X509_VERIFY_PARAM> SSL_get0_param(
    ffi.Pointer<SSL> ssl,
  ) {
    return _SSL_get0_param(
      ssl,
    );
  }

  late final _SSL_get0_paramPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<X509_VERIFY_PARAM> Function(
              ffi.Pointer<SSL>)>>('SSL_get0_param');
  late final _SSL_get0_param = _SSL_get0_paramPtr.asFunction<
      ffi.Pointer<X509_VERIFY_PARAM> Function(ffi.Pointer<SSL>)>();

  void SSL_free(
    ffi.Pointer<SSL> ssl,
  ) {
    return _SSL_free(
      ssl,
    );
  }

  late final _SSL_freePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<SSL>)>>(
          'SSL_free');
  late final _SSL_free =
      _SSL_freePtr.asFunction<void Function(ffi.Pointer<SSL>)>();

  int SSL_accept(
    ffi.Pointer<SSL> ssl,
  ) {
    return _SSL_accept(
      ssl,
    );
  }

  late final _SSL_acceptPtr =
      _lookup<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<SSL>)>>(
          'SSL_accept');
  late final _SSL_accept =
      _SSL_acceptPtr.asFunction<int Function(ffi.Pointer<SSL>)>();

  int SSL_connect(
    ffi.Pointer<SSL> ssl,
  ) {
    return _SSL_connect(
      ssl,
    );
  }

  late final _SSL_connectPtr =
      _lookup<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<SSL>)>>(
          'SSL_connect');
  late final _SSL_connect =
      _SSL_connectPtr.asFunction<int Function(ffi.Pointer<SSL>)>();

  int SSL_read(
    ffi.Pointer<SSL> ssl,
    ffi.Pointer<ffi.Void> buf,
    int num,
  ) {
    return _SSL_read(
      ssl,
      buf,
      num,
    );
  }

  late final _SSL_readPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(
              ffi.Pointer<SSL>, ffi.Pointer<ffi.Void>, ffi.Int)>>('SSL_read');
  late final _SSL_read = _SSL_readPtr.asFunction<
      int Function(ffi.Pointer<SSL>, ffi.Pointer<ffi.Void>, int)>();

  int SSL_write(
    ffi.Pointer<SSL> ssl,
    ffi.Pointer<ffi.Void> buf,
    int num,
  ) {
    return _SSL_write(
      ssl,
      buf,
      num,
    );
  }

  late final _SSL_writePtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(
              ffi.Pointer<SSL>, ffi.Pointer<ffi.Void>, ffi.Int)>>('SSL_write');
  late final _SSL_write = _SSL_writePtr.asFunction<
      int Function(ffi.Pointer<SSL>, ffi.Pointer<ffi.Void>, int)>();

  int SSL_ctrl(
    ffi.Pointer<SSL> ssl,
    int cmd,
    int larg,
    ffi.Pointer<ffi.Void> parg,
  ) {
    return _SSL_ctrl(
      ssl,
      cmd,
      larg,
      parg,
    );
  }

  late final _SSL_ctrlPtr = _lookup<
      ffi.NativeFunction<
          ffi.Long Function(ffi.Pointer<SSL>, ffi.Int, ffi.Long,
              ffi.Pointer<ffi.Void>)>>('SSL_ctrl');
  late final _SSL_ctrl = _SSL_ctrlPtr.asFunction<
      int Function(ffi.Pointer<SSL>, int, int, ffi.Pointer<ffi.Void>)>();

  int SSL_get_error(
    ffi.Pointer<SSL> s,
    int ret_code,
  ) {
    return _SSL_get_error(
      s,
      ret_code,
    );
  }

  late final _SSL_get_errorPtr =
      _lookup<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<SSL>, ffi.Int)>>(
          'SSL_get_error');
  late final _SSL_get_error =
      _SSL_get_errorPtr.asFunction<int Function(ffi.Pointer<SSL>, int)>();

  ffi.Pointer<SSL_METHOD> DTLS_server_method() {
    return _DTLS_server_method();
  }

  late final _DTLS_server_methodPtr =
      _lookup<ffi.NativeFunction<ffi.Pointer<SSL_METHOD> Function()>>(
          'DTLS_server_method');
  late final _DTLS_server_method =
      _DTLS_server_methodPtr.asFunction<ffi.Pointer<SSL_METHOD> Function()>();

  ffi.Pointer<SSL_METHOD> DTLS_client_method() {
    return _DTLS_client_method();
  }

  late final _DTLS_client_methodPtr =
      _lookup<ffi.NativeFunction<ffi.Pointer<SSL_METHOD> Function()>>(
          'DTLS_client_method');
  late final _DTLS_client_method =
      _DTLS_client_methodPtr.asFunction<ffi.Pointer<SSL_METHOD> Function()>();

  ffi.Pointer<stack_st_SSL_CIPHER> SSL_get1_supported_ciphers(
    ffi.Pointer<SSL> s,
  ) {
    return _SSL_get1_supported_ciphers(
      s,
    );
  }

  late final _SSL_get1_supported_ciphersPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<stack_st_SSL_CIPHER> Function(
              ffi.Pointer<SSL>)>>('SSL_get1_supported_ciphers');
  late final _SSL_get1_supported_ciphers =
      _SSL_get1_supported_ciphersPtr.asFunction<
          ffi.Pointer<stack_st_SSL_CIPHER> Function(ffi.Pointer<SSL>)>();

  int SSL_shutdown(
    ffi.Pointer<SSL> s,
  ) {
    return _SSL_shutdown(
      s,
    );
  }

  late final _SSL_shutdownPtr =
      _lookup<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<SSL>)>>(
          'SSL_shutdown');
  late final _SSL_shutdown =
      _SSL_shutdownPtr.asFunction<int Function(ffi.Pointer<SSL>)>();

  void SSL_set_accept_state(
    ffi.Pointer<SSL> s,
  ) {
    return _SSL_set_accept_state(
      s,
    );
  }

  late final _SSL_set_accept_statePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<SSL>)>>(
          'SSL_set_accept_state');
  late final _SSL_set_accept_state =
      _SSL_set_accept_statePtr.asFunction<void Function(ffi.Pointer<SSL>)>();

  int SSL_CTX_set_default_verify_paths(
    ffi.Pointer<SSL_CTX> ctx,
  ) {
    return _SSL_CTX_set_default_verify_paths(
      ctx,
    );
  }

  late final _SSL_CTX_set_default_verify_pathsPtr =
      _lookup<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<SSL_CTX>)>>(
          'SSL_CTX_set_default_verify_paths');
  late final _SSL_CTX_set_default_verify_paths =
      _SSL_CTX_set_default_verify_pathsPtr.asFunction<
          int Function(ffi.Pointer<SSL_CTX>)>();

  int DTLSv1_listen(
    ffi.Pointer<SSL> s,
    ffi.Pointer<BIO_ADDR> client,
  ) {
    return _DTLSv1_listen(
      s,
      client,
    );
  }

  late final _DTLSv1_listenPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(
              ffi.Pointer<SSL>, ffi.Pointer<BIO_ADDR>)>>('DTLSv1_listen');
  late final _DTLSv1_listen = _DTLSv1_listenPtr.asFunction<
      int Function(ffi.Pointer<SSL>, ffi.Pointer<BIO_ADDR>)>();

  void SSL_CTX_set_security_level(
    ffi.Pointer<SSL_CTX> ctx,
    int level,
  ) {
    return _SSL_CTX_set_security_level(
      ctx,
      level,
    );
  }

  late final _SSL_CTX_set_security_levelPtr = _lookup<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<SSL_CTX>, ffi.Int)>>(
      'SSL_CTX_set_security_level');
  late final _SSL_CTX_set_security_level = _SSL_CTX_set_security_levelPtr
      .asFunction<void Function(ffi.Pointer<SSL_CTX>, int)>();

  int ERR_get_error() {
    return _ERR_get_error();
  }

  late final _ERR_get_errorPtr =
      _lookup<ffi.NativeFunction<ffi.UnsignedLong Function()>>('ERR_get_error');
  late final _ERR_get_error = _ERR_get_errorPtr.asFunction<int Function()>();

  ffi.Pointer<ffi.Char> ERR_error_string(
    int e,
    ffi.Pointer<ffi.Char> buf,
  ) {
    return _ERR_error_string(
      e,
      buf,
    );
  }

  late final _ERR_error_stringPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<ffi.Char> Function(
              ffi.UnsignedLong, ffi.Pointer<ffi.Char>)>>('ERR_error_string');
  late final _ERR_error_string = _ERR_error_stringPtr.asFunction<
      ffi.Pointer<ffi.Char> Function(int, ffi.Pointer<ffi.Char>)>();
}

final class timeval extends ffi.Struct {
  @__time_t()
  external int tv_sec;

  @__suseconds_t()
  external int tv_usec;
}

typedef __time_t = ffi.Long;
typedef __suseconds_t = ffi.Long;
typedef BIO = bio_st;

final class bio_st extends ffi.Opaque {}

typedef BIO_METHOD = bio_method_st;

final class bio_method_st extends ffi.Opaque {}

typedef BIO_ADDR = bio_addr_st;

final class bio_addr_st extends ffi.Opaque {}

typedef X509_STORE = x509_store_st;

final class x509_store_st extends ffi.Opaque {}

typedef X509 = x509_st;

final class x509_st extends ffi.Opaque {}

typedef X509_VERIFY_PARAM = X509_VERIFY_PARAM_st;

final class X509_VERIFY_PARAM_st extends ffi.Opaque {}

typedef SSL_CTX = ssl_ctx_st;

final class ssl_ctx_st extends ffi.Opaque {}

typedef SSL = ssl_st;

final class ssl_st extends ffi.Opaque {}

typedef SSL_psk_client_cb_func
    = ffi.Pointer<ffi.NativeFunction<SSL_psk_client_cb_funcFunction>>;
typedef SSL_psk_client_cb_funcFunction = ffi.UnsignedInt Function(
    ffi.Pointer<SSL> ssl,
    ffi.Pointer<ffi.Char> hint,
    ffi.Pointer<ffi.Char> identity,
    ffi.UnsignedInt max_identity_len,
    ffi.Pointer<ffi.UnsignedChar> psk,
    ffi.UnsignedInt max_psk_len);
typedef DartSSL_psk_client_cb_funcFunction = int Function(
    ffi.Pointer<SSL> ssl,
    ffi.Pointer<ffi.Char> hint,
    ffi.Pointer<ffi.Char> identity,
    int max_identity_len,
    ffi.Pointer<ffi.UnsignedChar> psk,
    int max_psk_len);
typedef SSL_psk_server_cb_func
    = ffi.Pointer<ffi.NativeFunction<SSL_psk_server_cb_funcFunction>>;
typedef SSL_psk_server_cb_funcFunction = ffi.UnsignedInt Function(
    ffi.Pointer<SSL> ssl,
    ffi.Pointer<ffi.Char> identity,
    ffi.Pointer<ffi.UnsignedChar> psk,
    ffi.UnsignedInt max_psk_len);
typedef DartSSL_psk_server_cb_funcFunction = int Function(
    ffi.Pointer<SSL> ssl,
    ffi.Pointer<ffi.Char> identity,
    ffi.Pointer<ffi.UnsignedChar> psk,
    int max_psk_len);
typedef SSL_METHOD = ssl_method_st;

final class ssl_method_st extends ffi.Opaque {}

typedef SSL_verify_cb = ffi.Pointer<ffi.NativeFunction<SSL_verify_cbFunction>>;
typedef SSL_verify_cbFunction = ffi.Int Function(
    ffi.Int preverify_ok, ffi.Pointer<X509_STORE_CTX> x509_ctx);
typedef DartSSL_verify_cbFunction = int Function(
    int preverify_ok, ffi.Pointer<X509_STORE_CTX> x509_ctx);
typedef X509_STORE_CTX = x509_store_ctx_st;

final class x509_store_ctx_st extends ffi.Opaque {}

final class stack_st_SSL_CIPHER extends ffi.Opaque {}

const int BIO_C_SET_BUF_MEM_EOF_RETURN = 130;

const int SSL3_AL_FATAL = 2;

const int TLSEXT_NAMETYPE_host_name = 0;

const int SSL_VERIFY_NONE = 0;

const int SSL_VERIFY_PEER = 1;

const int SSL_AD_CLOSE_NOTIFY = 0;

const int SSL_AD_UNEXPECTED_MESSAGE = 10;

const int SSL_ERROR_SSL = 1;

const int SSL_ERROR_SYSCALL = 5;

const int SSL_ERROR_ZERO_RETURN = 6;

const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;

const int DTLS_CTRL_GET_TIMEOUT = 73;
