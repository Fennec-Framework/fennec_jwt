bool secureCompareIntList(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  int c = 0;
  for (int i = 0; i < a.length; i++) {
    c += a[i] ^ b[i];
  }
  return c == 0;
}
