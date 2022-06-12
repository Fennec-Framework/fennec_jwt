class JwtException implements Exception {
  final String message;
  const JwtException(this.message);
  @override
  String toString() => message;
  static const JwtException invalidToken = JwtException('Invalid JWT token!');
  static const JwtException headerNotJson =
      JwtException('Invalid JWT token: Header not JSON!');
  static const JwtException payloadNotJson =
      JwtException('Invalid JWT token: Payload not JSON!');
  static const JwtException hashMismatch = JwtException('JWT hash mismatch!');
  static const JwtException tokenExpired = JwtException('JWT token expired!');
  static const JwtException tokenNotYetAccepted =
      JwtException('JWT token not yet accepted!');
  static const JwtException tokenNotYetIssued =
      JwtException('JWT token not yet issued!');
  static const JwtException audienceNotAllowed =
      JwtException('Audience not allowed!');
  static const JwtException incorrectIssuer = JwtException('Incorrect issuer!');
}
