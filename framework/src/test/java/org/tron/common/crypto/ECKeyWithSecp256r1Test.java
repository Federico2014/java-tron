package org.tron.common.crypto;

import java.math.BigInteger;
import java.security.SignatureException;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.crypto.curveparams.Secp256r1Params;
import org.tron.common.utils.Sha256Hash;

public class ECKeyWithSecp256r1Test {

  @Test
  public void testCurveParams() {
    BigInteger p = new BigInteger(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    BigInteger a = new BigInteger(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    BigInteger b = new BigInteger(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    BigInteger gx = new BigInteger(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    BigInteger gy = new BigInteger(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    BigInteger n = new BigInteger(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    BigInteger h = new BigInteger(
        "1", 16);
    Secp256r1Params params = Secp256r1Params.getInstance();
    Assert.assertTrue(
        params.getCurve().getCurve().getField().getCharacteristic().compareTo(p) == 0);
    Assert.assertTrue(params.getCurve().getCurve().getA().toBigInteger().compareTo(a) == 0);
    Assert.assertTrue(params.getCurve().getCurve().getB().toBigInteger().compareTo(b) == 0);
    Assert.assertTrue(params.getCurve().getG().getRawXCoord().toBigInteger().compareTo(gx) == 0);
    Assert.assertTrue(params.getCurve().getG().getRawYCoord().toBigInteger().compareTo(gy) == 0);
    Assert.assertTrue(params.getCurve().getN().compareTo(n) == 0);
    Assert.assertTrue(params.getCurve().getH().compareTo(h) == 0);
  }

  @Test
  public void testSignAndVerify() {
    ECKey key = new ECKey(Secp256r1Params.getInstance());
    Assert.assertTrue(key.getPrivKey().compareTo(Secp256r1Params.getInstance().getN()) < 0);
    byte[] message = "Raw Transaction".getBytes();
    byte[] hash = Sha256Hash.hash(true, message);
    ECDSASignature signature = key.doSign(hash, Secp256r1Params.getInstance());
    Assert.assertTrue(
        ECKey.verify(Secp256r1Params.getInstance(), hash, signature, key.getPubKey()));
  }

  @Test
  public void testAddress() throws SignatureException {
    ECKey key = new ECKey(Secp256r1Params.getInstance());

    byte[] message = "Raw Transaction".getBytes();
    byte[] hash = Sha256Hash.hash(true, message);
    ECDSASignature signature = key.sign(hash, Secp256r1Params.getInstance());
    byte[] address = ECKey.signatureToAddress(hash, signature.toBase64(),
        Secp256r1Params.getInstance());
    Assert.assertArrayEquals(key.getAddress(), address);
  }
}
