import 'package:pointycastle/digests/gost3411.dart';

// GOST R 34.11 hash via PointyCastle
// EXPECTED: GOST3411 | hash | | info |
List<int> gostHash(List<int> data) {
  final digest = GOST3411Digest();
  return digest.process(data);
}
