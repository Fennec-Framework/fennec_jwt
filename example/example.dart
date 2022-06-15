import 'dart:math';

import 'package:fennec_jwt/fennec_jwt.dart';

final String sharedSecret = '123456';
void main(List<String> arguments) {
  final claimSet = JwtClaim(
    issuer: 'fennec_jwt',
    subject: 'jwt',
    audience: <String>['fennec_jwt@test.com'],
    jwtId: generateRandomString(32),
    otherClaims: <String, dynamic>{},
    maxAge: const Duration(minutes: 5),
  );
  final token = generateJwtHS256(claimSet, sharedSecret);

  print('JWT: "$token"\n');
  validateJwt(token);
}

void validateJwt(String token) {
  final claimSet = verifyJwtHS256Signature(token, sharedSecret);
  claimSet.validate(issuer: 'fennec_jwt', audience: 'fennec_jwt@test.com');
  print(claimSet.toJson());
}

String generateRandomString(int len) {
  var r = Random();
  return String.fromCharCodes(
      List.generate(len, (index) => r.nextInt(33) + 89));
}
