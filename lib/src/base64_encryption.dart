import 'dart:convert';

class Base64Encryption {
  Base64Encryption._();
  static String encode(List<int> octets) =>
      base64Url.encode(octets).replaceAll('=', ''); // padding removed
  static List<int> decodeBase64(String encoded) {
    String output = encoded.replaceAll('-', '+').replaceAll('_', '/');
    switch (output.length % 4) {
      case 0:
        break;
      case 2:
        output += '==';
        break;
      case 3:
        output += '=';
        break;
      default:
        throw const FormatException('Illegal base64url string!');
    }
    return base64Url.decode(output);
  }

  static String encodeUtf8(String str) => encode(utf8.encode(str));
  static String decodeUtf8(String encoded) =>
      utf8.decode(decodeBase64(encoded));
}
