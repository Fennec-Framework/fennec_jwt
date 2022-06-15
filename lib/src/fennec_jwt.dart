import 'dart:collection';
import 'dart:convert';

import '../fennec_jwt.dart';
import 'base64_encryption.dart';

import 'package:crypto/crypto.dart';

import 'secure_compare.dart';

String generateJwtHS256(JwtClaim claimSet, String hmacKey) {
  final hmac = Hmac(sha256, hmacKey.codeUnits);

  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'HS256', 'typ': 'JWT'});

  final String encHdr = Base64Encryption.encodeUtf8(json.encode(header));
  final String encPld =
      Base64Encryption.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '$encHdr.$encPld';
  final String encSig =
      Base64Encryption.encode(hmac.convert(data.codeUnits).bytes);
  return data + '.' + encSig;
}

String generateJwtHS1(JwtClaim claimSet, String hmacKey) {
  final hmac = Hmac(sha1, hmacKey.codeUnits);
  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'HS1', 'typ': 'JWT'});
  final String encHdr = Base64Encryption.encodeUtf8(json.encode(header));
  final String encPld =
      Base64Encryption.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '$encHdr.$encPld';
  final String encSig =
      Base64Encryption.encode(hmac.convert(data.codeUnits).bytes);
  return data + '.' + encSig;
}

String generateJwtHS512(JwtClaim claimSet, String hmacKey) {
  final hmac = Hmac(sha512, hmacKey.codeUnits);
  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'HS512', 'typ': 'JWT'});
  final String encHdr = Base64Encryption.encodeUtf8(json.encode(header));
  final String encPld =
      Base64Encryption.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '$encHdr.$encPld';
  final String encSig =
      Base64Encryption.encode(hmac.convert(data.codeUnits).bytes);
  return data + '.' + encSig;
}

String generateJwtMD5(JwtClaim claimSet, String hmacKey) {
  final hmac = Hmac(md5, hmacKey.codeUnits);
  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'MD5', 'typ': 'JWT'});
  final String encHdr = Base64Encryption.encodeUtf8(json.encode(header));
  final String encPld =
      Base64Encryption.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '$encHdr.$encPld';
  final String encSig =
      Base64Encryption.encode(hmac.convert(data.codeUnits).bytes);
  return data + '.' + encSig;
}

typedef JOSEHeaderCheck = bool Function(Map<String, dynamic> joseHeader);

bool defaultJWTHeaderCheck(Map<String, dynamic> h) {
  if (!h.containsKey('typ')) {
    return true;
  }

  final dynamic typ = h['typ'];
  return typ == 'JWT';
}

JwtClaim verifyJwtHS256Signature(String token, String hmacKey,
    {JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
    bool defaultIatExp = true,
    Duration maxAge = JwtClaim.defaultMaxAge}) {
  try {
    final hmac = Hmac(sha256, hmacKey.codeUnits);

    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    final headerString = Base64Encryption.decodeUtf8(parts[0]);

    final dynamic header = json.decode(headerString);
    if (header is Map) {
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS256') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);

    if (!secureCompareIntList(calcSig, tokenSig)) {
      throw JwtException.hashMismatch;
    }
    final payloadString = Base64Encryption.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload.cast(),
          defaultIatExp: defaultIatExp, maxAge: maxAge);
    } else {
      throw JwtException.payloadNotJson;
    }
  } on FormatException {
    throw JwtException.invalidToken;
  }
}

JwtClaim verifyJwtHS512Signature(String token, String hmacKey,
    {JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
    bool defaultIatExp = true,
    Duration maxAge = JwtClaim.defaultMaxAge}) {
  try {
    final hmac = Hmac(sha512, hmacKey.codeUnits);

    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    final headerString = Base64Encryption.decodeUtf8(parts[0]);

    final dynamic header = json.decode(headerString);
    if (header is Map) {
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS512') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);

    if (!secureCompareIntList(calcSig, tokenSig)) {
      throw JwtException.hashMismatch;
    }
    final payloadString = Base64Encryption.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload.cast(),
          defaultIatExp: defaultIatExp, maxAge: maxAge);
    } else {
      throw JwtException.payloadNotJson;
    }
  } on FormatException {
    throw JwtException.invalidToken;
  }
}

JwtClaim verifyJwtHS1Signature(String token, String hmacKey,
    {JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
    bool defaultIatExp = true,
    Duration maxAge = JwtClaim.defaultMaxAge}) {
  try {
    final hmac = Hmac(sha1, hmacKey.codeUnits);

    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    final headerString = Base64Encryption.decodeUtf8(parts[0]);

    final dynamic header = json.decode(headerString);
    if (header is Map) {
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS1') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);

    if (!secureCompareIntList(calcSig, tokenSig)) {
      throw JwtException.hashMismatch;
    }
    final payloadString = Base64Encryption.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload.cast(),
          defaultIatExp: defaultIatExp, maxAge: maxAge);
    } else {
      throw JwtException.payloadNotJson;
    }
  } on FormatException {
    throw JwtException.invalidToken;
  }
}

JwtClaim verifyJwtMD5Signature(String token, String hmacKey,
    {JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
    bool defaultIatExp = true,
    Duration maxAge = JwtClaim.defaultMaxAge}) {
  try {
    final hmac = Hmac(md5, hmacKey.codeUnits);

    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    final headerString = Base64Encryption.decodeUtf8(parts[0]);

    final dynamic header = json.decode(headerString);
    if (header is Map) {
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'MD5') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);

    if (!secureCompareIntList(calcSig, tokenSig)) {
      throw JwtException.hashMismatch;
    }
    final payloadString = Base64Encryption.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload.cast(),
          defaultIatExp: defaultIatExp, maxAge: maxAge);
    } else {
      throw JwtException.payloadNotJson;
    }
  } on FormatException {
    throw JwtException.invalidToken;
  }
}
