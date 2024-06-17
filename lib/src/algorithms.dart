// ignore_for_file: constant_identifier_names, public_member_api_docs

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'package:jsonwebtoken/src/exceptions.dart';

abstract class JWTAlgorithm {
  /// HMAC using SHA-256 hash algorithm
  static const HS256 = HMACAlgorithm('HS256');

  /// Return the `JWTAlgorithm` from his string name
  static JWTAlgorithm fromName(String name) {
    switch (name) {
      case 'HS256':
        return JWTAlgorithm.HS256;
      default:
        throw JWTInvalidException('unknown algorithm');
    }
  }

  const JWTAlgorithm();

  /// `JWTAlgorithm` name
  String get name;

  /// Create a signature of the `body` with `key`
  ///
  /// return the signature as bytes
  Uint8List sign(String key, Uint8List body);

  /// Verify the `signature` of `body` with `key`
  ///
  /// return `true` if the signature is correct `false` otherwise
  bool verify(String key, Uint8List body, Uint8List signature);
}

class HMACAlgorithm extends JWTAlgorithm {
  const HMACAlgorithm(this._name);

  final String _name;

  @override
  String get name => _name;

  @override
  Uint8List sign(String key, Uint8List body) {
    final secretKey = key;

    final hmac = Hmac(
      _getHash(name),
      utf8.encode(secretKey),
    );

    return Uint8List.fromList(hmac.convert(body).bytes);
  }

  @override
  bool verify(String key, Uint8List body, Uint8List signature) {
    final actual = sign(key, body);

    if (actual.length != signature.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] != signature[i]) return false;
    }

    return true;
  }

  Hash _getHash(String name) {
    switch (name) {
      case 'HS256':
        return sha256;
      default:
        throw ArgumentError.value(name, 'name', 'unknown hash name');
    }
  }
}
