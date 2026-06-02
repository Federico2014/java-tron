package org.tron.common.crypto.zksnark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

/**
 * Regression baseline for the alt_bn128 (BN254) curve primitives used by the
 * ecAdd / ecMul / ecPairing precompiles (addresses 0x06 / 0x07 / 0x08).
 *
 * <p>Prior to this class the BN128 stack ({@link BN128Fp}, {@link BN128G1},
 * {@link BN128G2}, {@link PairingCheck}) had no direct unit coverage — only the
 * gas-accounting paths were exercised through Solidity contracts in IstanbulTest.
 * These tests lock in point validation, generator membership, the G1 vs G2
 * subgroup-check asymmetry, and pairing correctness against known generators.
 *
 * <p>The G1 subgroup behaviour is the core of HackerOne report #3769516: because
 * the alt_bn128 G1 cofactor is 1, the on-curve check performed by
 * {@code BN128Fp.create} is itself the subgroup check, so every on-curve G1 point
 * is a valid group member and no separate isGroupMember() call is required.
 */
public class BN128Test {

  // 32-byte big-endian coordinates, parsed by Fp.create via new BigInteger(1, v).

  // G1 generator (1, 2)
  private static final byte[] G1_X =
      Hex.decode("0000000000000000000000000000000000000000000000000000000000000001");
  private static final byte[] G1_Y =
      Hex.decode("0000000000000000000000000000000000000000000000000000000000000002");
  // -G1 = (1, p - 2): affine negation, p is the F_p modulus.
  private static final byte[] G1_NEG_Y =
      Hex.decode("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45");

  // Subgroup order r of the alt_bn128 G1/G2 groups.
  private static final BigInteger R = new BigInteger(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617");

  // G2 generator: x = a + b*i, y = c + d*i  (EIP-197 standard generator).
  // BN128G2.create(a, b, c, d) expects this coordinate order.
  private static final byte[] G2_A =
      Hex.decode("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed");
  private static final byte[] G2_B =
      Hex.decode("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2");
  private static final byte[] G2_C =
      Hex.decode("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa");
  private static final byte[] G2_D =
      Hex.decode("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b");

  private static byte[] word(long v) {
    byte[] w = new byte[32];
    for (int i = 0; i < 8; i++) {
      w[31 - i] = (byte) (v >>> (8 * i));
    }
    return w;
  }

  // ---- BN128Fp / point-on-curve validation ----------------------------------

  @Test
  public void testG1GeneratorIsOnCurve() {
    assertNotNull("G1 generator (1,2) must be accepted", BN128G1.create(G1_X, G1_Y));
  }

  @Test
  public void testPointAtInfinityAccepted() {
    // (0, 0) encodes the point at infinity and must be accepted.
    assertNotNull(BN128G1.create(word(0), word(0)));
  }

  @Test
  public void testOffCurvePointRejected() {
    // (1, 1): y^2 = 1, x^3 + 3 = 4, not on the curve -> rejected.
    assertNull(BN128G1.create(word(1), word(1)));
  }

  @Test
  public void testCoordinateAboveFieldModulusRejected() {
    // x = p (the field modulus) is not a valid F_p element together with y = 2.
    byte[] pBytes =
        Hex.decode("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    assertNull(BN128G1.create(pBytes, G1_Y));
  }

  // ---- G1 subgroup behaviour (HackerOne #3769516) ---------------------------

  @Test
  public void testG1GeneratorHasOrderR() {
    // alt_bn128 G1 cofactor == 1, so any on-curve point is in the order-r
    // subgroup. Confirm the generator genuinely has order r: r * G == O.
    BN128G1 g = BN128G1.create(G1_X, G1_Y);
    assertNotNull(g);
    assertEquals("r * G must be the point at infinity", true, g.mul(R).isZero());
  }

  // ---- BN128G2 / subgroup check ---------------------------------------------

  @Test
  public void testG2GeneratorIsGroupMember() {
    assertNotNull("G2 generator must pass the subgroup check",
        BN128G2.create(G2_A, G2_B, G2_C, G2_D));
  }

  @Test
  public void testG2OffCurveRejected() {
    // All-ones coordinates are not on the twist curve -> rejected.
    byte[] one = word(1);
    assertNull(BN128G2.create(one, one, one, one));
  }

  // ---- PairingCheck correctness ---------------------------------------------

  @Test
  public void testPairingEmptyIsOne() {
    // The empty product is the identity; ecPairing of no pairs returns 1.
    PairingCheck check = PairingCheck.create();
    check.run();
    assertEquals(1, check.result());
  }

  @Test
  public void testPairingNegationCancels() {
    // e(G1, G2) * e(-G1, G2) == 1, the canonical pairing sanity check
    // (mirrors pairing([P1, -P1], [P2, P2]) == true).
    BN128G1 g1 = BN128G1.create(G1_X, G1_Y);
    BN128G1 negG1 = BN128G1.create(G1_X, G1_NEG_Y);
    BN128G2 g2 = BN128G2.create(G2_A, G2_B, G2_C, G2_D);
    assertNotNull(g1);
    assertNotNull(negG1);
    assertNotNull(g2);

    PairingCheck check = PairingCheck.create();
    check.addPair(g1, g2);
    check.addPair(negG1, g2);
    check.run();
    assertEquals("e(G1,G2)*e(-G1,G2) must equal 1", 1, check.result());
  }

  @Test
  public void testPairingSinglePairIsNotOne() {
    // e(G1, G2) alone is a non-trivial element, so the check returns 0.
    BN128G1 g1 = BN128G1.create(G1_X, G1_Y);
    BN128G2 g2 = BN128G2.create(G2_A, G2_B, G2_C, G2_D);

    PairingCheck check = PairingCheck.create();
    check.addPair(g1, g2);
    check.run();
    assertEquals(0, check.result());
  }
}
