package org.tron.common.crypto.zksnark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/**
 * Verifies the G2 subgroup acceptance rule used when decoding pairing inputs. The private
 * predicate is compared against the full-order oracle {@code [r]P = O} for affine, projective,
 * infinity, and non-subgroup points.
 */
public class BN128G2Test {

  private static final BigInteger TWO = BigInteger.valueOf(2);
  private static final BigInteger P = Params.P;
  private static final BigInteger SQRT_EXPONENT = P.add(BigInteger.ONE).shiftRight(2);

  // Standard alt_bn128 G2 generator, with Fp2 elements represented as a + b * i.
  private static final BigInteger G2_X_A = new BigInteger(
      "10857046999023057135944570762232829481370756359578518086990519993285655852781");
  private static final BigInteger G2_X_B = new BigInteger(
      "11559732032986387107991004021392285783925812861821192530917403151452391805634");
  private static final BigInteger G2_Y_A = new BigInteger(
      "8495653923123431417604973247489272438418190587263600148770280649306958101930");
  private static final BigInteger G2_Y_B = new BigInteger(
      "4082367875863433681332203403145435568316851327593401208105741076214120093531");

  @Test
  public void testInfinityIsGroupMember() {
    assertNotNull(BN128G2.create(bytes(0), bytes(0), bytes(0), bytes(0)));
  }

  @Test
  public void testGeneratorIsGroupMember() {
    assertNotNull(createG2(G2_X_A, G2_X_B, G2_Y_A, G2_Y_B));
  }

  @Test
  public void testPredicateMatchesFullOrderMultiplication() throws Exception {
    List<BN128<Fp2>> points = new ArrayList<>();
    BN128<Fp2> generator = createAffine(G2_X_A, G2_X_B, G2_Y_A, G2_Y_B);
    assertNotNull(generator);
    points.add(generator);
    points.addAll(curvePoints(6));

    boolean sawNonSubgroup = false;
    for (BN128<Fp2> point : points) {
      boolean inSubgroup = point.mul(Params.R).isZero();
      assertEquals("predicate disagrees with [r]P = O for " + point,
          inSubgroup, isGroupMember(point));

      BN128G2 accepted = createG2(
          new BigInteger(1, point.x.a.bytes()), new BigInteger(1, point.x.b.bytes()),
          new BigInteger(1, point.y.a.bytes()), new BigInteger(1, point.y.b.bytes()));
      assertEquals("[r]P = O disagrees with create() for " + point, inSubgroup, accepted != null);

      if (!inSubgroup) {
        sawNonSubgroup = true;
      }
    }
    assertTrue("expected at least one non-subgroup point", sawNonSubgroup);
  }

  @Test
  public void testPredicateMatchesFullOrderForProjectiveInputs() throws Exception {
    BN128<Fp2> generator = createAffine(G2_X_A, G2_X_B, G2_Y_A, G2_Y_B);
    assertNotNull(generator);
    for (int k = 1; k <= 4; k++) {
      BN128<Fp2> point = generator.mul(BigInteger.valueOf(k));
      assertEquals("projective input " + k,
          point.mul(Params.R).isZero(), isGroupMember(point));
    }
  }

  private static BN128G2 createG2(BigInteger xa, BigInteger xb, BigInteger ya, BigInteger yb) {
    return BN128G2.create(xa.toByteArray(), xb.toByteArray(), ya.toByteArray(), yb.toByteArray());
  }

  private static BN128<Fp2> createAffine(BigInteger xa, BigInteger xb, BigInteger ya,
      BigInteger yb) {
    return BN128Fp2.create(xa.toByteArray(), xb.toByteArray(), ya.toByteArray(), yb.toByteArray());
  }

  private static boolean isGroupMember(BN128<Fp2> point) throws Exception {
    Method method = BN128G2.class.getDeclaredMethod("isGroupMember", BN128.class);
    method.setAccessible(true);
    return (Boolean) method.invoke(null, point);
  }

  /**
   * Returns ordinary twist points that are on the curve but, with overwhelming probability,
   * outside the order-r subgroup.
   */
  private static List<BN128<Fp2>> curvePoints(int limit) {
    List<BN128<Fp2>> points = new ArrayList<>();
    for (int i = 1; i <= 500 && points.size() < limit; i++) {
      Fp2 x = new Fp2(BigInteger.valueOf(i), BigInteger.ZERO);
      Fp2 rhs = x.squared().mul(x).add(Params.B_Fp2);
      Fp2 y = sqrt(rhs);
      if (y == null || !y.squared().equals(rhs)) {
        continue;
      }
      BN128<Fp2> point = BN128Fp2.create(x.a.bytes(), x.b.bytes(), y.a.bytes(), y.b.bytes());
      if (point != null && !point.isZero()) {
        points.add(point);
      }
    }
    return points;
  }

  /** Computes a square root in Fp2, or null when the value is not a square. */
  private static Fp2 sqrt(Fp2 value) {
    BigInteger a = new BigInteger(1, value.a.bytes());
    BigInteger b = new BigInteger(1, value.b.bytes());
    BigInteger norm = a.multiply(a).add(b.multiply(b)).mod(P);
    BigInteger c = sqrtFp(norm);
    if (c == null) {
      return null;
    }
    Fp2 result = sqrtWith(value, c);
    return result != null ? result : sqrtWith(value, c.negate().mod(P));
  }

  private static Fp2 sqrtWith(Fp2 value, BigInteger c) {
    BigInteger a = new BigInteger(1, value.a.bytes());
    BigInteger b = new BigInteger(1, value.b.bytes());
    BigInteger twoInv = TWO.modInverse(P);
    BigInteger realRoot = sqrtFp(a.add(c).multiply(twoInv).mod(P));
    BigInteger imagRoot = sqrtFp(c.subtract(a).multiply(twoInv).mod(P));
    if (realRoot == null || imagRoot == null) {
      return null;
    }
    BigInteger imaginary = realRoot.multiply(imagRoot).shiftLeft(1).mod(P);
    if (imaginary.equals(b.mod(P))) {
      return new Fp2(new Fp(realRoot), new Fp(imagRoot));
    }
    if (imaginary.negate().mod(P).equals(b.mod(P))) {
      return new Fp2(new Fp(realRoot), new Fp(imagRoot.negate().mod(P)));
    }
    return null;
  }

  /** Square root in Fp for p = 3 (mod 4), or null when the value is not a square. */
  private static BigInteger sqrtFp(BigInteger value) {
    BigInteger v = value.mod(P);
    if (v.signum() == 0) {
      return BigInteger.ZERO;
    }
    BigInteger root = v.modPow(SQRT_EXPONENT, P);
    return root.multiply(root).mod(P).equals(v) ? root : null;
  }

  private static byte[] bytes(long value) {
    return BigInteger.valueOf(value).toByteArray();
  }
}
