
**fennec_jwt** is dart plugin for generate and validate jwt. it belongs to fennec framework (link)[https://github.com/Fennec-Framework/fennec] but it can be used 
separately.

# supported hashing algorithms:
- SHA-1

- SHA-256

- SHA-512

- MD5


# installation:

install the plugin from pub.dev


# usage


``` dart

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
  
```


# LICENSE

[MIT](https://github.com/Fennec-Framework/fennec_jwt/blob/master/LICENSE)



