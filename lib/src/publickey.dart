import 'base.dart';
import 'err.dart';

/// [PublicKey] represents a public key which is a point on a 2d [Curve],
///  taking [BigInt] X, Y as the coordinates on axis
class PublicKey extends AffinePoint {
  Curve curve;

  PublicKey(this.curve, BigInt X, BigInt Y) : super.fromXY(X, Y);

  PublicKey.fromPoint(this.curve, AffinePoint p) : super.fromXY(p.X, p.Y);

  /// [fromHex] will auto detect the hex type, which means hex can be compressed
  /// or not
  PublicKey.fromHex(this.curve, String hex) {
    if (hex.length <= 2) {
      throw ErrInvalidPublicKeyHexLength;
    }

    late PublicKey pub;
    var prefix = hex.substring(0, 2);
    switch (prefix) {
      case '02':
        pub = curve.compressedHexToPublicKey(hex);
        break;
      case '03':
        pub = curve.compressedHexToPublicKey(hex);
        break;
      case '04':
        pub = curve.hexToPublicKey(hex);
        break;
      default:
        throw ErrInvalidPublicKeyHexPrefix;
    }

    X = pub.X;
    Y = pub.Y;
  }

  /// [toHex] generate a compressed hex string from a public key
  String toHex() {
    return curve.publicKeyToHex(this);
  }

  /// [toCompressedHex] generate a compressed hex string from a public key
  String toCompressedHex() {
    return curve.publicKeyToCompressedHex(this);
  }

  /// [toString] equals to [toHex]
  @override
  String toString() {
    return toHex();
  }

  @override
  bool operator ==(other) {
    return other is PublicKey && (curve == other.curve && X == other.X && Y == other.Y);
  }

  PublicKey tweakAdd(BigInt tweak) {
    // Compute the new public key after adding the tweak
    AffinePoint tweakedKey = curve.add(this, scalarMultiply(curve.G, tweak));

    return PublicKey.fromPoint(curve, tweakedKey);
  }

  AffinePoint scalarMultiply(AffinePoint point, BigInt scalar) {
    AffinePoint result = AffinePoint.fromXY(BigInt.zero, BigInt.zero);
    AffinePoint current = point;

    while (scalar > BigInt.zero) {
      if (scalar.isOdd) {
        result = curve.add(result, current);
      }
      current = curve.dou(current);
      scalar >>= 1;
    }

    return result;
  }

  PublicKey? tweakMul(BigInt tweak) {
    // Perform the tweak multiplication
    AffinePoint tweakedPoint = scalarMultiply(this, tweak);

    // Verify the validity of the resulting public key (implementation depends on your library)
    if (isValidPublicKey(tweakedPoint, curve)) {
      X = tweakedPoint.X;
      Y = tweakedPoint.Y;
      return this; // Tweak multiplication successful
    } else {
      // Handle the case where the tweak resulted in an invalid public key
      // You can reset the public key or take appropriate action
      X = BigInt.zero; // Reset X to an invalid value
      Y = BigInt.zero; // Reset Y to an invalid value
      return null;
    }
  }

  bool isValidPublicKey(AffinePoint publicKey, Curve curve) {
    // Check if the public key's coordinates are both zero.
    if (publicKey.X == BigInt.zero && publicKey.Y == BigInt.zero) {
      return false; // Point at infinity
    }

    // Check if the public key's coordinates are within the curve's field size.
    final BigInt p = curve.p;
    final BigInt x = publicKey.X;
    final BigInt y = publicKey.Y;

    if (x < BigInt.zero || x >= p || y < BigInt.zero || y >= p) {
      return false;
    }

    // Check if the public key satisfies the curve equation: y^2 = x^3 + 7 (mod p)
    final BigInt ySquared = (y * y) % p;
    final BigInt xCubedPlus7 = (x * x * x + BigInt.from(7)) % p;

    if (ySquared != xCubedPlus7) {
      return false;
    }

    return true;
  }

  PublicKey negate() {
    // Negate the Y-coordinate by subtracting it from the field size (p).
    Y = curve.p - Y;

    return this; // Always return 1 to indicate success
  }
}
