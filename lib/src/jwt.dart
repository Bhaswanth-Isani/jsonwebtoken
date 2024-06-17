// ignore_for_file: avoid_dynamic_calls

import 'dart:convert';
import 'dart:typed_data';

import 'package:clock/clock.dart';

import 'package:jsonwebtoken/src/algorithms.dart';
import 'package:jsonwebtoken/src/exceptions.dart';
import 'package:jsonwebtoken/src/helpers.dart';

/// JSON Web Token
class JWT {
  /// JSON Web Token
  JWT();

  /// Verify a token.
  ///
  /// `key` must be
  /// - SecretKey with HMAC algorithm
  /// - RSAPublicKey with RSA algorithm
  /// - ECPublicKey with ECDSA algorithm
  /// - EdDSAPublicKey with EdDSA algorithm
  static dynamic verify(
    String token,
    String key, {
    bool checkHeaderType = true,
    bool checkExpiresIn = true,
    bool checkNotBefore = true,
    Duration? issueAt,
  }) {
    try {
      final parts = token.split('.');
      final header = jsonBase64.decode(base64Padded(parts[0]));

      if (header == null || header is! Map<String, dynamic>) {
        throw JWTInvalidException('invalid header');
      }

      if (checkHeaderType && header['typ'] != 'JWT') {
        throw JWTInvalidException('not a jwt');
      }

      final algorithm = JWTAlgorithm.fromName(header['alg'] as String);

      final body = utf8.encode('${parts[0]}.${parts[1]}');
      final signature = base64Url.decode(base64Padded(parts[2]));

      if (!algorithm.verify(key, Uint8List.fromList(body), signature)) {
        throw JWTInvalidException('invalid signature');
      }

      dynamic payload;

      try {
        payload = jsonBase64.decode(base64Padded(parts[1]));
      } catch (ex) {
        payload = utf8.decode(base64.decode(base64Padded(parts[1])));
      }

      if (payload is Map) {
        // exp
        if (checkExpiresIn && payload.containsKey('exp')) {
          final exp = DateTime.fromMillisecondsSinceEpoch(
            ((payload['exp'] as double) * 1000).toInt(),
          );
          if (exp.isBefore(clock.now())) {
            throw JWTExpiredException();
          }
        }

        // nbf
        if (checkNotBefore && payload.containsKey('nbf')) {
          final nbf = DateTime.fromMillisecondsSinceEpoch(
            ((payload['nbf'] as double) * 1000).toInt(),
          );
          if (nbf.isAfter(clock.now())) {
            throw JWTNotActiveException();
          }
        }

        // iat
        if (issueAt != null) {
          if (!payload.containsKey('iat')) {
            throw JWTInvalidException('invalid issue at');
          }
          final iat = DateTime.fromMillisecondsSinceEpoch(
            ((payload['iat'] as double) * 1000).toInt(),
          );
          if (!iat.isAtSameMomentAs(clock.now())) {
            throw JWTInvalidException('invalid issue at');
          }
        }

        return payload;
      } else {
        return payload;
      }
    } catch (ex, stackTrace) {
      if (ex is Exception && ex is! JWTException) {
        throw JWTUndefinedException(ex, stackTrace);
      } else {
        rethrow;
      }
    }
  }

  /// Exactly like `verify`, just return null instead of throwing exceptions.
  static dynamic tryVerify(
    String token,
    String key, {
    bool checkHeaderType = true,
    bool checkExpiresIn = true,
    bool checkNotBefore = true,
    Duration? issueAt,
    String? subject,
    String? issuer,
    String? jwtId,
  }) {
    try {
      return verify(
        token,
        key,
        checkHeaderType: checkHeaderType,
        checkExpiresIn: checkExpiresIn,
        checkNotBefore: checkNotBefore,
        issueAt: issueAt,
      );
    } catch (ex) {
      return null;
    }
  }

  /// Decode a token without checking its signature
  static dynamic decode(String token) {
    try {
      final parts = token.split('.');

      dynamic payload;

      try {
        payload = jsonBase64.decode(base64Padded(parts[1]));
      } catch (ex) {
        payload = utf8.decode(base64.decode(base64Padded(parts[1])));
      }

      return payload;
    } catch (ex, stackTrace) {
      if (ex is Exception && ex is! JWTException) {
        throw JWTUndefinedException(ex, stackTrace);
      } else {
        rethrow;
      }
    }
  }

  /// Exactly like `decode`, just return `null` instead of throwing exceptions.
  static dynamic tryDecode(String token) {
    try {
      return decode(token);
    } catch (ex) {
      return null;
    }
  }

  /// JWT header

  /// Sign and generate a new token.
  ///
  /// `key` must be
  /// - SecretKey with HMAC algorithm
  /// - RSAPrivateKey with RSA algorithm
  /// - ECPrivateKey with ECDSA algorithm
  /// - EdDSAPrivateKey with EdDSA algorithm
  static String sign(
    dynamic payload,
    String key, {
    JWTAlgorithm algorithm = JWTAlgorithm.HS256,
    Duration? expiresIn,
    Duration? notBefore,
    bool noIssueAt = false,
    Map<String, dynamic>? header,
  }) {
    try {
      if (payload is Map<String, dynamic> || payload is Map<dynamic, dynamic>) {
        try {
          if (!noIssueAt) payload['iat'] = secondsSinceEpoch(clock.now());
          if (expiresIn != null) {
            payload['exp'] = secondsSinceEpoch(clock.now().add(expiresIn));
          }
          if (notBefore != null) {
            payload['nbf'] = secondsSinceEpoch(clock.now().add(notBefore));
          }
        } catch (ex) {
          assert(
            payload is Map<String, dynamic>,
            'If payload is a Map its must be a Map<String, dynamic>',
          );
        }
      }

      // ignore: inference_failure_on_instance_creation
      final tokenHeader = Map.from(header ?? <String, dynamic>{})
        ..putIfAbsent('alg', () => algorithm.name)
        ..putIfAbsent('typ', () => 'JWT');

      final b64Header = base64Unpadded(jsonBase64.encode(tokenHeader));

      String b64Payload;
      try {
        b64Payload = base64Unpadded(
          payload is String
              ? base64.encode(utf8.encode(payload))
              : jsonBase64.encode(payload),
        );
      } catch (ex) {
        throw JWTException(
          'invalid payload json format (Map keys must be String type)',
        );
      }

      final body = '$b64Header.$b64Payload';
      final signature = base64Unpadded(
        base64Url.encode(
          algorithm.sign(
            key,
            Uint8List.fromList(utf8.encode(body)),
          ),
        ),
      );

      return '$body.$signature';
    } catch (ex, stackTrace) {
      if (ex is Exception && ex is! JWTException) {
        throw JWTUndefinedException(ex, stackTrace);
      } else {
        rethrow;
      }
    }
  }

  /// Exactly like `sign`, just return `null` instead of throwing exceptions.
  static String? trySign(
    dynamic payload,
    String key, {
    JWTAlgorithm algorithm = JWTAlgorithm.HS256,
    Duration? expiresIn,
    Duration? notBefore,
    bool noIssueAt = false,
    Map<String, dynamic>? header,
  }) {
    try {
      return sign(
        payload,
        key,
        algorithm: algorithm,
        expiresIn: expiresIn,
        notBefore: notBefore,
        noIssueAt: noIssueAt,
        header: header,
      );
    } catch (ex) {
      return null;
    }
  }
}

// /// Audience claim. Can contains one or more audience entry, used like a list
// ///
// /// To get only one audience you can use `.first` getter (list cannot be empty)
// ///
// /// To create a single audience you can use the factory `Audience.one('...')`.
// class Audience extends ListBase<String> {
//   /// Audience claim. Can contains one or more audience entry, used like a list
//   ///
//   /// To get only one audience you can use `.first` getter (list cannot be empty)
//   ///
//   /// To create a single audience you can use the factory `Audience.one('...')`.
//   Audience(this._audiences) : assert(_audiences.isNotEmpty, 'Audience cannot be empty');

//   /// Factory to create a single audience
//   factory Audience.one(String val) => Audience([val]);

//   final List<String> _audiences;

//   @override
//   int get length => _audiences.length;
//   @override
//   set length(int newLength) => _audiences.length = newLength;

//   @override
//   String operator [](int index) => _audiences[index];
//   @override
//   void operator []=(int index, String value) => _audiences[index] = value;

//   @override
//   void add(String element) => _audiences.add(element);
//   @override
//   void addAll(Iterable<String> iterable) => _audiences.addAll(iterable);

//   /// Returns json representation of the audience
//   dynamic toJson() {
//     if (_audiences.length == 1) {
//       return first;
//     } else {
//       return _audiences;
//     }
//   }
// }
