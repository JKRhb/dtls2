// Copyright (c) 2022 Jan Romann
// Copyright (c) 2021 Famedly GmbH
// SPDX-License-Identifier: MIT

import "dart:ffi";

import "package:ffi/ffi.dart";

/// Size of the global buffer used for interacting with OpenSSL.
const bufferSize = 1 << 16;

/// Global buffer used for interacting with OpenSSL.
final Pointer<Uint8> buffer = malloc.call<Uint8>(bufferSize);
