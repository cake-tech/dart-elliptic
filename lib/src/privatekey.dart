import 'base.dart';
import 'publickey.dart';

class PrivateKey {
  late Curve curve;
  late BigInt D;

  PrivateKey(this.curve, this.D);

  PrivateKey.fromBytes(this.curve, List<int> bytes, {bool compress = false}) {
    var byteLen = (curve.bitSize + 7) >> 3;
    D = BigInt.parse(
        List<String>.generate(byteLen, (i) => bytes[i].toRadixString(16).padLeft(2, '0')).join(),
        radix: 16);

    if (compress) {
      var pub = curve.privateToPublicKey(this);
      D = pub.Y.isOdd ? pub.X + curve.n : pub.X;
    }
  }

  PrivateKey.fromHex(this.curve, String hexRand) {
    D = BigInt.parse(hexRand, radix: 16);
  }

  /// [bytes] will calculate the bytes for the private key's [D]
  List<int> get bytes {
    var byteLen = (curve.bitSize + 7) >> 3;
    var hex = D.toRadixString(16).padLeft(byteLen * 2, '0'); // to bigendian
    return List<int>.generate(
        byteLen, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16));
  }

  /// [publicKey] will calculate the public key for the private key
  PublicKey get publicKey {
    return curve.privateToPublicKey(this);
  }

  String toHex() {
    var byteLen = (curve.bitSize + 7) >> 3;
    return D.toRadixString(16).padLeft(byteLen * 2, '0');
  }

  @override
  String toString() {
    return toHex();
  }

  /// [toCompressedHex] generate a compressed hex string from a private key
  String toCompressedHex() {
    var byteLen = (this.curve.bitSize + 7) >> 3;
    var hex = this.D.toRadixString(16).padLeft(byteLen * 2, '0');
    return hex;
  }

  @override
  bool operator ==(other) {
    return other is PrivateKey && (curve == other.curve && D == other.D);
  }

  PrivateKey? tweakAdd(BigInt tweak) {
    D = (D + tweak) % curve.n;

    if (isValidPrivateKey(D, curve)) {
      return this; // Tweak addition successful
    } else {
      return null;
    }
  }

  PrivateKey? tweakMul(BigInt tweak) {
    // Check if the private key and tweak are valid
    if (!isValidPrivateKey(D, curve) || tweak >= curve.n) {
      return null; // Invalid private key or tweak
    }

    // Perform the tweak multiplication
    D = (D * tweak) % curve.n;

    return this; // Tweak multiplication successful
  }

  PrivateKey? negate() {
    if (isValidPrivateKey(D, curve)) {
      D = curve.n - D; // Negate the private key by subtracting from the order of the curve
      return this;
    } else {
      return null; // Private key is invalid
    }
  }

  bool isValidPrivateKey(BigInt privateKey, Curve curve) {
    // Ensure the private key is not zero and is within the range [1, n-1]
    return (privateKey != BigInt.zero) && (privateKey < curve.n);
  }
}
