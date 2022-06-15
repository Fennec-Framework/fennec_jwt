import 'dart:collection';

class Utils {
  Utils._();
  static SplayTreeMap<String, dynamic> _splayify(Map map) {
    final data = SplayTreeMap<String, dynamic>();

    map.forEach((k, v) {
      if (k is String) {
        data[k] = splay(v);
      } else {
        throw const FormatException('Map with non-String key');
      }
    });

    return data;
  }

  static dynamic splay(dynamic value) {
    if (value is Iterable) {
      return value.map<dynamic>(splay).toList();
    } else if (value is Map) {
      return _splayify(value);
    } else {
      return value;
    }
  }
}
