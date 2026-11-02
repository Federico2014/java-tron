package org.tron.common.crypto.zksnark;

import java.math.BigInteger;
import java.util.Random;
import org.junit.Assert;
import org.junit.Test;

public class BN128G2Test {

  private static final BigInteger SQRT_EXPONENT = Params.P.add(BigInteger.ONE).shiftRight(2);
  private static final BigInteger TWO_INVERSE = BigInteger.valueOf(2).modInverse(Params.P);

  @Test
  public void testInfinityAndInvalidCoordinates() {
    byte[] zero = new byte[32];
    Assert.assertTrue(BN128G2.create(zero, zero, zero, zero).isZero());
    Assert.assertNull(BN128G2.create(new byte[]{1}, zero, new byte[]{1}, zero));
    for (int i = 0; i < 4; i++) {
      byte[][] coordinates = {zero, zero, zero, zero};
      coordinates[i] = Params.P.toByteArray();
      Assert.assertNull(BN128G2.create(coordinates[0], coordinates[1],
          coordinates[2], coordinates[3]));
    }
  }

  @Test
  public void testGeneratorMultiplesMatchFullOrderCheck() {
    BN128<Fp2> generator = generator();
    BigInteger[] boundary = {BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2),
        Params.R.subtract(BigInteger.ONE), Params.R, Params.R.add(BigInteger.ONE)};
    for (BigInteger scalar : boundary) {
      assertMembership(generator.mul(scalar), true);
    }
    Random random = new Random(40L);
    for (int i = 0; i < 32; i++) {
      assertMembership(generator.mul(new BigInteger(254, random)), true);
    }
  }

  @Test
  public void testCurvePointsAndCofactorComponentsMatchFullOrderCheck() {
    Random random = new Random(41L);
    BN128<Fp2> generator = generator();
    BigInteger cofactor = Params.P.shiftLeft(1).subtract(Params.R);
    for (int i = 0; i < 32; i++) {
      BN128<Fp2> point = randomCurvePoint(random);
      assertMembership(point, false);
      // The sextic-twist endomorphism satisfies psi^4 - psi^2 + 1 = 0
      // on the whole twist, including points outside the r-torsion subgroup.
      BN128G2 psi2 = new BN128G2(point).mulByP().mulByP();
      BN128G2 psi4 = psi2.mulByP().mulByP();
      Assert.assertTrue(psi4.add(point)
          .add(new BN128G2(psi2.x, psi2.y.negate(), psi2.z)).isZero());
      // Remove the r-torsion component, and also test points with both components.
      BN128<Fp2> torsion = point.mul(Params.R);
      assertMembership(torsion, false);
      assertMembership(torsion.add(generator.mul(BigInteger.valueOf(i + 1))), false);
      assertMembership(point.mul(cofactor), true);
      assertMembership(new BN128Fp2(point.x, point.y.negate(), point.z), false);
    }
  }

  @Test
  public void testMulByPMatchesScalarOnProjectiveSubgroupPoints() {
    BN128<Fp2> generator = generator();
    Random random = new Random(42L);
    for (int i = 0; i < 16; i++) {
      BN128G2 point = new BN128G2(generator.mul(new BigInteger(254, random)));
      Fp2 x = point.x;
      Fp2 y = point.y;
      Fp2 z = point.z;
      BN128<Fp2> expected = point.mul(Params.P).toAffine();
      BN128<Fp2> actual = point.mulByP().toAffine();
      // BN128.equals() also compares the concrete Java class.
      Assert.assertEquals(expected.x, actual.x);
      Assert.assertEquals(expected.y, actual.y);
      Assert.assertEquals(expected.z, actual.z);
      Assert.assertEquals(x, point.x);
      Assert.assertEquals(y, point.y);
      Assert.assertEquals(z, point.z);
    }
  }

  @Test
  public void testPrimeOrderCofactorPointsAreRejected() {
    BigInteger cofactor = Params.P.shiftLeft(1).subtract(Params.R);
    BigInteger[] factors = {BigInteger.valueOf(10069), BigInteger.valueOf(5864401),
        new BigInteger("1875725156269"),
        new BigInteger("197620364512881247228717050342013327560683201906968909")};
    BigInteger product = BigInteger.ONE;
    for (BigInteger factor : factors) {
      product = product.multiply(factor);
    }
    Assert.assertEquals(cofactor, product);
    BN128<Fp2> point = randomCurvePoint(new Random(43L));
    for (BigInteger factor : factors) {
      BN128<Fp2> torsion = point.mul(Params.R.multiply(cofactor.divide(factor)));
      Assert.assertFalse(torsion.isZero());
      Assert.assertTrue(torsion.mul(factor).isZero());
      assertMembership(torsion, false);
      assertMembership(torsion.add(generator()), false);
    }
  }

  private static void assertMembership(BN128<Fp2> point, boolean expected) {
    Assert.assertTrue(point.isValid());
    Assert.assertEquals(expected, point.mul(Params.R).isZero());
    BN128<Fp2> affine = point.toEthNotation();
    BN128G2 decoded = BN128G2.create(affine.x.a.bytes(), affine.x.b.bytes(),
        affine.y.a.bytes(), affine.y.b.bytes());
    Assert.assertEquals(expected, decoded != null);
    if (decoded != null) {
      Assert.assertEquals(affine.x, decoded.x);
      Assert.assertEquals(affine.y, decoded.y);
      Assert.assertEquals(affine.z, decoded.z);
    }
  }

  private static BN128<Fp2> generator() {
    return new BN128Fp2(
        new BigInteger(
            "10857046999023057135944570762232829481370756359578518086990519993285655852781"),
        new BigInteger(
            "11559732032986387107991004021392285783925812861821192530917403151452391805634"),
        new BigInteger(
            "8495653923123431417604973247489272438418190587263600148770280649306958101930"),
        new BigInteger(
            "4082367875863433681332203403145435568316851327593401208105741076214120093531"));
  }

  private static BN128<Fp2> randomCurvePoint(Random random) {
    // Construct points on the whole twist, independently of the G2 decoder.
    for (int attempt = 0; attempt < 128; attempt++) {
      Fp2 x = new Fp2(new BigInteger(254, random).mod(Params.P),
          new BigInteger(254, random).mod(Params.P));
      Fp2 rhs = x.squared().mul(x).add(Params.B_Fp2);
      BigInteger a = new BigInteger(rhs.a.bytes());
      BigInteger b = new BigInteger(rhs.b.bytes());
      BigInteger norm = a.multiply(a).add(b.multiply(b)).mod(Params.P);
      BigInteger root = sqrt(norm);
      if (root == null) {
        continue;
      }
      for (BigInteger sign : new BigInteger[]{root, Params.P.subtract(root).mod(Params.P)}) {
        BigInteger real = sqrt(a.add(sign).multiply(TWO_INVERSE).mod(Params.P));
        if (real == null || real.signum() == 0) {
          continue;
        }
        BigInteger imaginary = b.multiply(real.shiftLeft(1).modInverse(Params.P)).mod(Params.P);
        Fp2 y = new Fp2(real, imaginary);
        Assert.assertEquals(rhs, y.squared());
        return new BN128Fp2(x, y, Fp2._1);
      }
    }
    throw new AssertionError("Could not construct a twist point");
  }

  private static BigInteger sqrt(BigInteger value) {
    BigInteger root = value.modPow(SQRT_EXPONENT, Params.P);
    return root.multiply(root).mod(Params.P).equals(value) ? root : null;
  }
}
