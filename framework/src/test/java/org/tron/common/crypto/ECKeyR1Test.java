package org.tron.common.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.crypto.curveparams.Secp256r1Params;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.PublicMethod;
import org.tron.common.utils.Sha256Hash;

@Slf4j
public class ECKeyR1Test {

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
    ECDSASignature signature = key.doSign(hash);
    Assert.assertTrue(
        ECKey.verify(Secp256r1Params.getInstance(), hash, signature, key.getPubKey()));
  }

  @Test
  public void testAddress() throws SignatureException {
    ECKey key = new ECKey(Secp256r1Params.getInstance());

    byte[] message = "Raw Transaction".getBytes();
    byte[] hash = Sha256Hash.hash(true, message);
    ECDSASignature signature = key.sign(hash);
    byte[] address = ECKey.signatureToAddress(hash, signature.toBase64(),
        Secp256r1Params.getInstance());
    Assert.assertArrayEquals(key.getAddress(), address);
  }

  @Test
  public void testSignatureMalleability() throws SignatureException {
    ECKey key = new ECKey(Secp256r1Params.getInstance());
    byte[] randomBytes = new byte[128];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);
    ECDSASignature signature = key.sign(msgHash);

    byte[] pubKeyBytes = ECKey.signatureToKeyBytes(msgHash, signature.toBase64(),
        Secp256r1Params.getInstance());
    Assert.assertArrayEquals(pubKeyBytes, key.getPubKey());

    Assert.assertTrue(
        signature.s.compareTo(Secp256r1Params.getInstance().getHalfCurveOrder()) <= 0);
    BigInteger flipS = Secp256r1Params.getInstance().getCurve().getN().subtract(signature.s);
    Assert.assertTrue(flipS.compareTo(Secp256r1Params.getInstance().getHalfCurveOrder()) > 0);

    byte[] flipPubKeyBytes = ECKey.signatureToKeyBytes(msgHash,
        ECDSASignature.fromComponents(signature.r.toByteArray(), flipS.toByteArray(), signature.v)
            .toBase64(), Secp256r1Params.getInstance());
    Assert.assertNotEquals(ByteArray.toHexString(flipPubKeyBytes),
        ByteArray.toHexString(key.getPubKey()));

    byte flipV;
    if (signature.v <= 28) {
      flipV = signature.v == 27 ? (byte) 28 : (byte) 27;
    } else {
      flipV = signature.v == 29 ? (byte) 30 : (byte) 29;
    }

    flipPubKeyBytes = ECKey.signatureToKeyBytes(msgHash,
        ECDSASignature.fromComponents(signature.r.toByteArray(), flipS.toByteArray(), flipV)
            .toBase64(), Secp256r1Params.getInstance());
    Assert.assertArrayEquals(flipPubKeyBytes, key.getPubKey());
  }

  @Test
  public void testInvalidSignature() throws SignatureException {
    byte[] randomBytes = new byte[128];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    String privString = PublicMethod.getRandomPrivateKey();
    SignInterface ecKey = ECKey.fromPrivate(ByteArray.fromHexString(privString),
        Secp256r1Params.getInstance());
    String signature = ((ECKey) ecKey).signHash(msgHash);

    byte[] address = ECKey.signatureToAddress(msgHash, signature, Secp256r1Params.getInstance());
    Assert.assertArrayEquals(address, ecKey.getAddress());

    ECDSASignature ecdsaSignature;
    byte[] signatureEncoded = Base64.decode(signature);
    byte[] r = new byte[32];
    byte[] s = new byte[32];
    System.arraycopy(signatureEncoded, 1, r, 0, 32);
    System.arraycopy(signatureEncoded, 33, s, 0, 32);
    byte v = signatureEncoded[0];

    for (int i = 0; i < 32; i++) {
      byte[] r2 = Arrays.copyOf(r, r.length);
      r2[i] = (byte) (r2[i] + 1);
      ecdsaSignature = ECDSASignature.fromComponents(r2, s, v);
      try {
        byte[] ecdsaAddress = ECKey.signatureToAddress(msgHash, ecdsaSignature,
            Secp256r1Params.getInstance());
        Assert.assertNotEquals(ByteArray.toHexString(ecdsaAddress), ByteArray.toHexString(address));
      } catch (SignatureException e) {
        Assert.assertEquals(e.getMessage(), "Could not parse pub key");
      } catch (IllegalArgumentException e) {
        Assert.assertEquals(e.getMessage(), "Invalid point compression");
      }
    }

    for (int i = 0; i < 32; i++) {
      byte[] s2 = Arrays.copyOf(s, s.length);
      s2[i] = (byte) (s2[i] + 1);
      ecdsaSignature = ECDSASignature.fromComponents(r, s2, v);

      byte[] ecdsaAddress = ECKey.signatureToAddress(msgHash, ecdsaSignature,
          Secp256r1Params.getInstance());
      Assert.assertNotEquals(ByteArray.toHexString(ecdsaAddress), ByteArray.toHexString(address));
    }

    for (int i = 27; i < 60; i++) {
      byte v2 = (byte) (i);
      if (v2 == v || v2 == v + 4) {
        continue;
      }
      ecdsaSignature = ECDSASignature.fromComponents(r, s, v2);
      try {
        byte[] ecdsaAddress = ECKey.signatureToAddress(msgHash, ecdsaSignature,
            Secp256r1Params.getInstance());
        Assert.assertNotEquals(ByteArray.toHexString(ecdsaAddress), ByteArray.toHexString(address));
      } catch (Exception e) {
        Assert.assertTrue(e instanceof SignatureException);
      }
    }

    ecdsaSignature = ECDSASignature.fromComponents(r, s, v);
    byte[] ecdsaAddress = ECKey.signatureToAddress(msgHash, ecdsaSignature,
        Secp256r1Params.getInstance());
    Assert.assertArrayEquals(ecdsaAddress, address);
  }

  @Ignore
  @Test
  public void ecKeySignBench() throws SignatureException {
    byte[] randomBytes = new byte[128];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(randomBytes);
    String privString = PublicMethod.getRandomPrivateKey();
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    ECKey ecKeyK1 = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    int iterations = 10000;
    // warm up
    for (int i = 0; i < iterations; i++) {
      ecKeyK1.signHash(msgHash);
    }
    long startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ecKeyK1.signHash(msgHash);
    }
    long endTime = System.nanoTime();
    long durationNs = endTime - startTime;
    long nsPerIteration = durationNs / iterations;
    logger.info("ECKeyK1 sign cost: " + nsPerIteration + "ns per call");

    ECKey ecKeyR1 = ECKey.fromPrivate(ByteArray.fromHexString(privString),
        Secp256r1Params.getInstance());
    // warm up
    for (int i = 0; i < iterations; i++) {
      ecKeyR1.signHash(msgHash);
    }
    startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ecKeyR1.signHash(msgHash);
    }
    endTime = System.nanoTime();
    durationNs = endTime - startTime;
    long nsPerIterationV2 = durationNs / iterations;
    logger.info("ECKeyR1 sign cost: " + nsPerIterationV2 + "ns per call");
    logger.info("ECKeyK1/ECKeyR1: " + (double) nsPerIteration / nsPerIterationV2);
  }

  @Ignore
  @Test
  public void ecKeyVerifyBench() throws SignatureException {
    byte[] randomBytes = new byte[128];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(randomBytes);
    String privString = PublicMethod.getRandomPrivateKey();
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    ECKey ecKeyK1 = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    String signature = ecKeyK1.signHash(msgHash);
    int iterations = 10000;
    // warm up
    for (int i = 0; i < iterations; i++) {
      ECKey.signatureToAddress(msgHash, signature);
    }
    long startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ECKey.signatureToAddress(msgHash, signature);
    }
    long endTime = System.nanoTime();
    long durationNs = endTime - startTime;
    long nsPerIteration = durationNs / iterations;
    logger.info("ECKeyK1 verify cost: " + nsPerIteration + "ns per call");

    ECKey ecKeyR1 = ECKey.fromPrivate(ByteArray.fromHexString(privString),
        Secp256r1Params.getInstance());
    String signatureV2 = ecKeyR1.signHash(msgHash);

    // warm up
    for (int i = 0; i < iterations; i++) {
      ECKey.signatureToAddress(msgHash, signatureV2, Secp256r1Params.getInstance());
    }
    startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ECKey.signatureToAddress(msgHash, signatureV2, Secp256r1Params.getInstance());
    }
    endTime = System.nanoTime();
    durationNs = endTime - startTime;
    long nsPerIterationV2 = durationNs / iterations;
    logger.info("ECKeyR1 verify cost: " + nsPerIterationV2 + "ns per call");
    logger.info("ECKeyK1/ECKeyR1: " + (double) nsPerIteration / nsPerIterationV2);
  }
}
