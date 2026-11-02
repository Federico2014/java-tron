package org.tron.common.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.tron.common.utils.DecodeUtil;

public class HashTest {

  @Test
  public void testComputeAddressRejectsPointAtInfinity() {
    assertThrows(IllegalArgumentException.class,
        () -> Hash.computeAddress(ECKey.CURVE.getCurve().getInfinity()));
  }

  @Test
  public void testComputeAddressPreservesPublicKeyAddress() {
    byte[] publicKey = Hex.decode(
        "04e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e625529"
            + "392df7fa514bdd65a2003f6619567d79bee89830e63e932dbd42362d34");
    ECPoint point = ECKey.CURVE.getCurve().decodePoint(publicKey);
    byte[] expected = Hex.decode("412e988a386a799f506693793c6a5af6b54dfaabfb");
    expected[0] = DecodeUtil.addressPreFixByte;

    assertArrayEquals(expected, Hash.computeAddress(point));
    assertArrayEquals(expected, Hash.computeAddress(publicKey));
    assertArrayEquals(expected, ECKey.fromPublicOnly(publicKey).getAddress());
    assertArrayEquals(expected, ECKey.fromPublicOnly(point.getEncoded(true)).getAddress());
  }

  @Test
  public void testComputeAddressPreservesLegacyInfinityEncoding() {
    byte[] expected = Hex.decode("41dcc703c0e500b653ca82273b7bfad8045d85a470");
    expected[0] = DecodeUtil.addressPreFixByte;

    assertArrayEquals(expected, Hash.computeAddress(new byte[]{0}));
  }
}
