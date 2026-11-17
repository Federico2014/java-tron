package org.tron.common.crypto.zksnark;

import java.math.BigInteger;
import org.junit.Assert;
import org.junit.Test;

public class PairingCheckTest {

  @Test
  public void testHomogeneousAcceptsAffinePoint() {
    BN128G2 affine = new BN128G2(Fp2._1, Fp2._1, Fp2._1);

    PairingCheck.G2Homogeneous point = PairingCheck.G2Homogeneous.fromAffine(affine);

    Assert.assertEquals(Fp2._1, point.x);
    Assert.assertEquals(Fp2._1, point.y);
    Assert.assertEquals(Fp2._1, point.z);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testHomogeneousRejectsJacobianPoint() {
    BN128G2 nonAffine =
        new BN128G2(Fp2._1, Fp2._1, Fp2.create(BigInteger.valueOf(2), BigInteger.ZERO));

    PairingCheck.G2Homogeneous.fromAffine(nonAffine);
  }
}
