package org.tron.common.crypto.zksnark;

import java.math.BigInteger;
import java.util.Random;
import org.junit.Assert;
import org.junit.Test;

public class Fp2Test {

  @Test
  public void testToStringUsesRealThenImaginaryCoefficient() {
    Assert.assertEquals("1 + 0i", Fp2._1.toString());
    Assert.assertEquals("0 + 1i", new Fp2(BigInteger.ZERO, BigInteger.ONE).toString());
    Assert.assertEquals("9 + 1i", Fp2.NON_RESIDUE.toString());
  }

  @Test
  public void testOperationsAgainstDirectFormulaForBoundaryValues() {
    BigInteger[] values = {BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2),
        Params.P.subtract(BigInteger.valueOf(2)), Params.P.subtract(BigInteger.ONE)};
    for (BigInteger a : values) {
      for (BigInteger b : values) {
        for (BigInteger c : values) {
          for (BigInteger d : values) {
            assertOperations(new Fp2(a, b), new Fp2(c, d));
          }
        }
      }
    }
  }

  @Test
  public void testOperationsAgainstDirectFormulaForRandomValues() {
    Random random = new Random(38L);
    for (int i = 0; i < 256; i++) {
      assertOperations(randomElement(random), randomElement(random));
    }
  }

  @Test
  public void testInverseOfZeroStillThrows() {
    Assert.assertThrows(ArithmeticException.class, () -> Fp2.ZERO.inverse());
    Assert.assertEquals(new Fp2(BigInteger.ZERO, BigInteger.ZERO), Fp2.ZERO);
  }

  @Test
  public void testExtensionFieldOperations() {
    Random random = new Random(39L);
    Fp6 first = new Fp6(randomElement(random), randomElement(random), randomElement(random));
    Fp6 second = new Fp6(randomElement(random), randomElement(random), randomElement(random));
    Assert.assertEquals(first.mul(first), first.squared());
    Assert.assertEquals(Fp6._1, first.mul(first.inverse()));

    Fp12 value = new Fp12(first, second);
    Assert.assertEquals(value.mul(value), value.squared());
    Assert.assertEquals(Fp12._1, value.mul(value.inverse()));
  }

  private static Fp2 randomElement(Random random) {
    return new Fp2(new BigInteger(Params.P.bitLength(), random).mod(Params.P),
        new BigInteger(Params.P.bitLength(), random).mod(Params.P));
  }

  private static void assertOperations(Fp2 left, Fp2 right) {
    BigInteger a = new BigInteger(left.a.bytes());
    BigInteger b = new BigInteger(left.b.bytes());
    BigInteger c = new BigInteger(right.a.bytes());
    BigInteger d = new BigInteger(right.b.bytes());
    Fp2 leftBefore = new Fp2(left.a, left.b);
    Fp2 rightBefore = new Fp2(right.a, right.b);

    assertElement(a.multiply(a).subtract(b.multiply(b)), a.multiply(b).shiftLeft(1),
        left.squared());
    assertElement(a.multiply(c).subtract(b.multiply(d)), a.multiply(d).add(b.multiply(c)),
        left.mul(right));
    Assert.assertEquals(left.mul(left), left.squared());
    assertElement(a.multiply(BigInteger.valueOf(9)).subtract(b),
        a.add(b.multiply(BigInteger.valueOf(9))), left.mulByNonResidue());
    Assert.assertEquals(Fp2.NON_RESIDUE.mul(left), left.mulByNonResidue());

    if (!left.isZero()) {
      BigInteger inverse = a.multiply(a).add(b.multiply(b)).mod(Params.P).modInverse(Params.P);
      assertElement(a.multiply(inverse), b.multiply(inverse).negate(), left.inverse());
      Assert.assertEquals(Fp2._1, left.mul(left.inverse()));
    }
    Assert.assertEquals(leftBefore, left);
    Assert.assertEquals(rightBefore, right);
    Assert.assertEquals(new Fp2(BigInteger.valueOf(9), BigInteger.ONE), Fp2.NON_RESIDUE);
  }

  private static void assertElement(BigInteger real, BigInteger imaginary, Fp2 actual) {
    Assert.assertEquals(new Fp2(real.mod(Params.P), imaginary.mod(Params.P)), actual);
    Assert.assertTrue(actual.isValid());
  }
}
