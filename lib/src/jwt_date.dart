import 'jwt_exception.dart';

class JwtDate {
  JwtDate._();
  static DateTime? decode(dynamic value) {
    if (value == null) {
      return null;
    } else if (value is int) {
      if (0 <= value) {
        return DateTime.fromMillisecondsSinceEpoch(value * 1000, isUtc: true);
      } else {
        throw JwtException.invalidToken;
      }
    } else if (value is double) {
      if (value.isFinite && 0.0 < value) {
        return DateTime.fromMillisecondsSinceEpoch((value * 1000).round(),
            isUtc: true);
      } else {
        throw JwtException.invalidToken;
      }
    } else {
      throw JwtException.invalidToken;
    }
  }

  static int encode(DateTime value) {
    value = value.toUtc();
    return value.millisecondsSinceEpoch ~/ 1000;
  }
}
