import 'dart:collection';
import 'dart:convert';

import 'package:fennec_jwt/src/claim_converter.dart';
import 'package:fennec_jwt/src/splay.dart';

import '../fennec_jwt.dart';
import 'jwt_date.dart';

class JwtClaim {
  JwtClaim(
      {this.issuer,
      this.subject,
      this.audience,
      DateTime? expiry,
      DateTime? notBefore,
      DateTime? issuedAt,
      this.jwtId,
      Map<String, dynamic>? otherClaims,
      Map<String, dynamic>? payload,
      bool defaultIatExp = true,
      Duration? maxAge})
      : issuedAt = issuedAt?.toUtc() ??
            ((defaultIatExp) ? DateTime.now().toUtc() : null),
        notBefore = notBefore?.toUtc(),
        expiry = expiry?.toUtc() ??
            ((defaultIatExp)
                ? ((issuedAt?.toUtc() ?? DateTime.now().toUtc())
                    .add(maxAge ?? defaultMaxAge))
                : null) {
    if (otherClaims != null) {
      for (String k in otherClaims.keys) {
        if (registeredClaimNames.contains(k)) {
          throw ArgumentError.value(k, 'otherClaims',
              'registred claim not permmitted in otherClaims');
        }
      }
      _otherClaims.addAll(otherClaims);
    }
    if (payload != null) {
      _otherClaims['pld'] = payload;
    }
  }
  factory JwtClaim.fromMap(Map<dynamic, dynamic> data,
      {bool defaultIatExp = true, Duration? maxAge}) {
    final singleStringValue = <String, String>{};
    for (var claimName in ['iss', 'sub', 'jti']) {
      if (data.containsKey(claimName)) {
        final v = data[claimName];
        if (v is String) {
          singleStringValue[claimName] = v;
        } else {
          throw JwtException.invalidToken;
        }
      }
    }

    List<String>? audienceList;
    if (data.containsKey('aud')) {
      audienceList = <String>[];

      final aud = data['aud'];
      if (aud is String) {
        audienceList.add(aud);
      } else if (aud is List) {
        for (var a in aud) {
          if (a is String) {
            audienceList.add(a);
          } else {
            throw JwtException.invalidToken;
          }
        }
      } else {
        throw JwtException.invalidToken;
      }
    }

    final expOrNull = JwtDate.decode(data['exp']);
    final notBeforeOrNull = JwtDate.decode(data['nbf']);
    final issuedAtOrNull = JwtDate.decode(data['iat']);

    final others = <String, dynamic>{};
    data.forEach((k, v) {
      if (k is String) {
        if (!registeredClaimNames.contains(k)) {
          others[k] = v;
        }
      } else {
        throw JwtException.invalidToken;
      }
    });

    return JwtClaim(
        issuer: singleStringValue['iss'],
        subject: singleStringValue['sub'],
        audience: audienceList,
        expiry: expOrNull,
        notBefore: notBeforeOrNull,
        issuedAt: issuedAtOrNull,
        jwtId: singleStringValue['jti'],
        otherClaims: (others.isNotEmpty) ? others : null,
        defaultIatExp: defaultIatExp,
        maxAge: maxAge);
  }
  String? issuer;
  String? subject;
  List<String>? audience;
  DateTime? expiry;
  DateTime? notBefore;
  DateTime? issuedAt;
  String? jwtId;
  final _otherClaims = <String, dynamic>{};
  bool containsKey(String claimName) {
    if (!registeredClaimNames.contains(claimName)) {
      return _otherClaims.containsKey(claimName);
    } else {
      switch (claimName) {
        case 'iss':
          return issuer != null;
        case 'sub':
          return subject != null;
        case 'aud':
          return audience != null;
        case 'exp':
          return expiry != null;
        case 'nbf':
          return notBefore != null;
        case 'iat':
          return issuedAt != null;
        case 'jti':
          return jwtId != null;
        default:
          throw UnsupportedError('bad non-registered claim: $claimName');
      }
    }
  }

  dynamic operator [](String claimName) {
    if (!registeredClaimNames.contains(claimName)) {
      return _otherClaims[claimName];
    } else {
      switch (claimName) {
        case 'iss':
          return issuer;
        case 'sub':
          return subject;
        case 'aud':
          return audience;
        case 'exp':
          return expiry;
        case 'nbf':
          return notBefore;
        case 'iat':
          return issuedAt;
        case 'jti':
          return jwtId;
        default:
          throw UnsupportedError('bad non-registered claim: $claimName');
      }
    }
  }

  Iterable<String> claimNames({bool includeRegisteredClaims = true}) {
    if (includeRegisteredClaims) {
      final populatedClaims = <String>[];

      for (var name in registeredClaimNames) {
        if (containsKey(name)) {
          populatedClaims.add(name);
        }
      }

      populatedClaims.addAll(_otherClaims.keys);

      return populatedClaims;
    } else {
      return _otherClaims.keys;
    }
  }

  Map<String, dynamic> get payload {
    final pld = _otherClaims['pld'];

    if (pld is Map<String, dynamic> || pld == null) {
      return pld as Map<String, dynamic>;
    }

    throw Exception('Invalid payload type found in the JWT token!');
  }

  void validate(
      {String? issuer,
      String? audience,
      Duration? allowedClockSkew,
      DateTime? currentTime}) {
    final absClockSkew = allowedClockSkew?.abs() ?? const Duration();

    if (issuer != null) {
      if (issuer != this.issuer) {
        throw JwtException.incorrectIssuer;
      }
    }
    if (audience != null) {
      if (this.audience != null && !this.audience!.contains(audience)) {
        throw JwtException.audienceNotAllowed;
      }
    }
    if (expiry != null && notBefore != null && !expiry!.isAfter(notBefore!)) {
      throw JwtException.invalidToken;
    }
    if (expiry != null && issuedAt != null && !expiry!.isAfter(issuedAt!)) {
      throw JwtException.invalidToken;
    }
    final cTime = (currentTime ?? DateTime.now()).toUtc();
    if (expiry != null && !cTime.isBefore(expiry!.add(absClockSkew))) {
      throw JwtException.tokenExpired;
    }
    if (notBefore != null && notBefore!.subtract(absClockSkew).isAfter(cTime)) {
      throw JwtException.tokenNotYetAccepted;
    }
  }

  Map<String, dynamic> toJson() {
    final body = SplayTreeMap<String, dynamic>();

    if (issuer != null) {
      body['iss'] = issuer!;
    }
    if (subject != null) {
      body['sub'] = subject!;
    }
    if (audience != null) {
      body['aud'] = audience!;
    }
    if (expiry != null) {
      body['exp'] = JwtDate.encode(expiry!);
    }
    if (notBefore != null) {
      body['nbf'] = JwtDate.encode(notBefore!);
    }
    if (issuedAt != null) {
      body['iat'] = JwtDate.encode(issuedAt!);
    }
    if (jwtId != null) {
      body['jti'] = jwtId!;
    }

    _otherClaims.forEach((k, v) {
      assert(!body.containsKey(k));
      try {
        body[k] = splay(v);
      } on FormatException catch (e) {
        throw JsonUnsupportedObjectError('JWT claim: $k (${e.message})');
      }
    });

    return body;
  }

  @override
  String toString() => claimConverter(this);
  static const List<String> registeredClaimNames = [
    'iss',
    'sub',
    'aud',
    'exp',
    'nbf',
    'iat',
    'jti'
  ];
  static const Duration defaultMaxAge = Duration(hours: 12);
}
