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

/// Header checking function type used by [verifyJwtHS256Signature].
typedef JOSEHeaderCheck = bool Function(Map<String, dynamic> joseHeader);

/// Default JOSE Header checker.
///
/// Returns true (header is ok) if the 'typ' Header Parameter is absent, or it
/// is present with the exact value of 'JWT'. Otherwise, false (header is
/// rejected).
///
/// This implementation allows [verifyJwtHS256Signature] to exactly replicate
/// its previous behaviour.
///.
/// Note: this check is more restrictive than what RFC 7519 requires, since the
/// value of 'JWT' is only a recommendation and it is supposed to be case
/// insensitive. See <https://tools.ietf.org/html/rfc7519#section-5.1>
bool defaultJWTHeaderCheck(Map<String, dynamic> h) {
  if (!h.containsKey('typ')) {
    return true;
  }

  final dynamic typ = h['typ'];
  return typ == 'JWT';
}

/// Verifies the signature and extracts the claim set from a JWT.
///
/// The signature is verified using the [hmacKey] with the HMAC SHA-256
/// algorithm.
///
/// The [headerCheck] is an optional function to check the header.
/// It defaults to [defaultJWTHeaderCheck].
///
/// Normally, if either the _Issued At Claim_ and/or _Expiration Time Claim_
/// are not present, default values are assigned to them.
/// This behaviour can be disabled by setting [defaultIatExp] to false.
/// See the constructor [JwtClaim] for details about what default values are
/// used and how [maxAge] is used.
///
/// Throws a [JwtException] if the signature does not verify or the
/// JWT is invalid.
///
///     final decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet);
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

    // Decode header and payload
    final headerString = Base64Encryption.decodeUtf8(parts[0]);
    // Check header
    final dynamic header = json.decode(headerString);
    if (header is Map) {
      // Perform any custom checks on the header
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS256') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);
    // Signature does not match calculated
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

    // Decode header and payload
    final headerString = Base64Encryption.decodeUtf8(parts[0]);
    // Check header
    final dynamic header = json.decode(headerString);
    if (header is Map) {
      // Perform any custom checks on the header
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS512') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);
    // Signature does not match calculated
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

    // Decode header and payload
    final headerString = Base64Encryption.decodeUtf8(parts[0]);
    // Check header
    final dynamic header = json.decode(headerString);
    if (header is Map) {
      // Perform any custom checks on the header
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS1') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);
    // Signature does not match calculated
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

    // Decode header and payload
    final headerString = Base64Encryption.decodeUtf8(parts[0]);
    // Check header
    final dynamic header = json.decode(headerString);
    if (header is Map) {
      // Perform any custom checks on the header
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'MD5') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = Base64Encryption.decodeBase64(parts[2]);
    // Signature does not match calculated
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
