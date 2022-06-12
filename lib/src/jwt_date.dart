import 'jwt_exception.dart';

class JwtDate {
  JwtDate._();
  static DateTime? decode(dynamic value) {
    if (value == null) {
      // Absent
      return null;
    } else if (value is int) {
      // Integer
      if (0 <= value) {
        return DateTime.fromMillisecondsSinceEpoch(value * 1000, isUtc: true);
      } else {
        throw JwtException.invalidToken; // negative
      }
    } else if (value is double) {
      // Double
      if (value.isFinite && 0.0 < value) {
        return DateTime.fromMillisecondsSinceEpoch((value * 1000).round(),
            isUtc: true);
      } else {
        throw JwtException.invalidToken; // NAN, +ve infinity or negative
      }
    } else {
      throw JwtException.invalidToken; // not an integer, nor a double
    }
  }

  static int encode(DateTime value) {
    value = value.toUtc();
    return value.millisecondsSinceEpoch ~/ 1000;
  }
}
