package org.tron.common.runtime.vm;

import java.math.BigInteger;
import java.util.Random;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.zksnark.BN128;
import org.tron.common.crypto.zksnark.BN128G1;
import org.tron.common.crypto.zksnark.Fp;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;

public class Bn128PrecompileTest {

  private static final BigInteger P = new BigInteger(
      "21888242871839275222246405745257275088696311157297823662689037894645226208583");
  private static final BigInteger[] G2 = {
      new BigInteger(
          "11559732032986387107991004021392285783925812861821192530917403151452391805634"),
      new BigInteger(
          "10857046999023057135944570762232829481370756359578518086990519993285655852781"),
      new BigInteger(
          "4082367875863433681332203403145435568316851327593401208105741076214120093531"),
      new BigInteger(
          "8495653923123431417604973247489272438418190587263600148770280649306958101930")
  };

  @Test
  public void testAdditionAndMultiplicationKnownPoint() {
    // Independently double (1, 2) using the affine tangent formula on y^2 = x^3 + 3.
    BigInteger slope = BigInteger.valueOf(3).multiply(BigInteger.valueOf(4).modInverse(P));
    BigInteger x = slope.multiply(slope).subtract(BigInteger.valueOf(2)).mod(P);
    BigInteger y = slope.multiply(BigInteger.ONE.subtract(x)).subtract(BigInteger.valueOf(2));
    byte[] expected = words(x, y.mod(P));
    assertResult(new PrecompiledContracts.BN128Addition(),
        words(BigInteger.ONE, BigInteger.valueOf(2), BigInteger.ONE, BigInteger.valueOf(2)),
        expected);
    assertResult(new PrecompiledContracts.BN128Multiplication(),
        words(BigInteger.ONE, BigInteger.valueOf(2), BigInteger.valueOf(2)), expected);
  }

  @Test
  public void testPairingFalseAndCancellationVectors() {
    for (int count : new int[]{1, 2, 4}) {
      for (byte[] input : pairingInputs(count)) {
        assertResult(pairing(), input, new DataWord(count == 1 ? 0 : 1).getData());
      }
    }
  }

  @Test
  public void testEmptyInfinityAndInvalidInputs() {
    PrecompiledContract addition = new PrecompiledContracts.BN128Addition();
    PrecompiledContract multiplication = new PrecompiledContracts.BN128Multiplication();
    PrecompiledContract pairing = pairing();
    for (byte[] empty : new byte[][]{null, new byte[0]}) {
      assertResult(addition, empty, new byte[64]);
      assertResult(multiplication, empty, new byte[64]);
      assertResult(pairing, empty, new DataWord(1).getData());
    }
    assertResult(pairing, new byte[192], new DataWord(1).getData());
    assertRejected(pairing.execute(new byte[191]));
    assertRejected(addition.execute(words(P, BigInteger.valueOf(2))));
    assertRejected(multiplication.execute(words(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)));
    byte[] invalidPair = pairingInputs(1)[0].clone();
    System.arraycopy(words(P), 0, invalidPair, 64, 32);
    assertRejected(pairing.execute(invalidPair));
  }

  static PrecompiledContracts.BN128Pairing pairing() {
    PrecompiledContracts.BN128Pairing result = new PrecompiledContracts.BN128Pairing();
    result.setVmShouldEndInUs(Long.MAX_VALUE / 1000);
    return result;
  }

  static byte[][] pairingInputs(int count) {
    byte[][] result = new byte[8][192 * count];
    BN128<Fp>[] points = points();
    for (int i = 0; i < result.length; i++) {
      for (int j = 0; j < count; j++) {
        BN128<Fp> point = points[(i + j / 2) % points.length];
        BigInteger y = value(point.y());
        if (j % 2 == 1) {
          y = P.subtract(y);
        }
        byte[] pair = words(value(point.x()), y, G2[0], G2[1], G2[2], G2[3]);
        System.arraycopy(pair, 0, result[i], j * 192, pair.length);
      }
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  private static BN128<Fp>[] points() {
    BN128G1 generator = BN128G1.create(new byte[]{1}, new byte[]{2});
    Assert.assertNotNull(generator);
    BN128<Fp>[] points = new BN128[16];
    Random random = new Random(380L);
    for (int i = 0; i < points.length; i++) {
      points[i] = generator.mul(new BigInteger(253, random).setBit(252)).toEthNotation();
    }
    return points;
  }

  private static BigInteger value(Fp coefficient) {
    return new BigInteger(coefficient.bytes());
  }

  private static byte[] words(BigInteger... values) {
    byte[] result = new byte[32 * values.length];
    for (int i = 0; i < values.length; i++) {
      byte[] raw = values[i].toByteArray();
      int start = raw.length > 32 ? raw.length - 32 : 0;
      System.arraycopy(raw, start, result, i * 32 + 32 - (raw.length - start), raw.length - start);
    }
    return result;
  }

  private static void assertResult(PrecompiledContract contract, byte[] input, byte[] expected) {
    Pair<Boolean, byte[]> actual = contract.execute(input);
    Assert.assertTrue(actual.getLeft());
    Assert.assertArrayEquals(expected, actual.getRight());
  }

  private static void assertRejected(Pair<Boolean, byte[]> result) {
    Assert.assertFalse(result.getLeft());
    Assert.assertArrayEquals(new byte[0], result.getRight());
  }
}
