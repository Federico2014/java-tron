package org.tron.common.crypto;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.PublicMethod;
import org.tron.common.utils.Sha256Hash;

@Slf4j
public class ECKeyV2Test {

  private String privString;
  private SecureRandom secureRandom = new SecureRandom();

  @Test
  public void testLibraryLoading() {
    assertTrue("Native ECKeyV2 library should be loaded", ECKeyV2.isECKeyV2Available());
  }

  @Test
  public void testECKeyV2() throws Exception {
    ECKey ecKey = new ECKey();
    ECKeyV2 ecKeyV2 = ECKeyV2.fromECKey(ecKey);
    Assert.assertArrayEquals(ecKey.getPubKey(), ecKeyV2.getPubKey());
    Assert.assertArrayEquals(ecKey.getAddress(), ecKeyV2.getAddress());

    ecKeyV2 = new ECKeyV2();
    ecKey = ECKey.fromPrivate(ecKeyV2.getPrivateKey());
    assert ecKey != null;
    Assert.assertArrayEquals(ecKey.getPubKey(), ecKeyV2.getPubKey());
    Assert.assertArrayEquals(ecKey.getAddress(), ecKeyV2.getAddress());

    ecKey = new ECKey();
    ecKeyV2 = ECKeyV2.fromPrivate(ecKey.getPrivateKey());
    assert ecKeyV2 != null;
    Assert.assertArrayEquals(ecKey.getPubKey(), ecKeyV2.getPubKey());
    Assert.assertArrayEquals(ecKey.getAddress(), ecKeyV2.getAddress());
  }

  @Test
  public void testSignature() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    privString = PublicMethod.getRandomPrivateKey();
    SignInterface ecKey = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    String signature = ecKey.signHash(msgHash);
    byte[] signatureBytes = ecKey.Base64toBytes(signature);

    SignInterface ecKeyV2 = ECKeyV2.fromPrivate(ByteArray.fromHexString(privString));
    String signatureV2 = ecKeyV2.signHash(msgHash);
    byte[] signatureBytesV2 = ecKeyV2.Base64toBytes(signatureV2);

    Assert.assertEquals(signature, signatureV2);
    Assert.assertArrayEquals(signatureBytes, signatureBytesV2);
  }

  @Test
  public void testVerifySignature() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    privString = PublicMethod.getRandomPrivateKey();

    SignInterface ecKeyV2 = ECKeyV2.fromPrivate(ByteArray.fromHexString(privString));
    String signatureV2 = ecKeyV2.signHash(msgHash);
    byte[] pubKeyBytes = ECKeyV2.signatureToKeyBytes(msgHash, signatureV2);
    Assert.assertArrayEquals(pubKeyBytes, ecKeyV2.getPubKey());

    byte[] address = ECKeyV2.signatureToAddress(msgHash, signatureV2);
    Assert.assertArrayEquals(address, ecKeyV2.getAddress());

    byte[] ecKeyAddress = ECKey.signatureToAddress(msgHash, signatureV2);
    Assert.assertArrayEquals(address, ecKeyAddress);

    ECDSASignature ecdsaSignature = ECDSASignature.parseBase64Signature(signatureV2);
    byte[] ecdaaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
    Assert.assertArrayEquals(address, ecdaaAddress);
  }

  @Test
  public void testVerifySignature2() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    privString = PublicMethod.getRandomPrivateKey();

    SignInterface ecKey = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    String signature = ecKey.signHash(msgHash);
    byte[] pubKeyBytes = ECKeyV2.signatureToKeyBytes(msgHash, signature);
    Assert.assertArrayEquals(pubKeyBytes, ecKey.getPubKey());

    byte[] address = ECKeyV2.signatureToAddress(msgHash, signature);
    Assert.assertArrayEquals(address, ecKey.getAddress());

    byte[] ecKeyAddress = ECKey.signatureToAddress(msgHash, signature);
    Assert.assertArrayEquals(address, ecKeyAddress);

    ECDSASignature ecdsaSignature = ECDSASignature.parseBase64Signature(signature);
    byte[] ecdaaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
    Assert.assertArrayEquals(address, ecdaaAddress);
  }

  @Test
  public void testInvalidSignature() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    privString = PublicMethod.getRandomPrivateKey();
    SignInterface ecKeyV2 = ECKeyV2.fromPrivate(ByteArray.fromHexString(privString));
    String signatureV2 = ecKeyV2.signHash(msgHash);

    byte[] address = ECKeyV2.signatureToAddress(msgHash, signatureV2);
    Assert.assertArrayEquals(address, ecKeyV2.getAddress());

    ECDSASignature ecdsaSignature = ECDSASignature.parseBase64Signature(signatureV2);
    byte[] r = ByteUtil.bigIntegerToBytes(ecdsaSignature.r, 32);
    byte[] s = ByteUtil.bigIntegerToBytes(ecdsaSignature.s, 32);
    byte v = ecdsaSignature.v;

    for (int i = 0; i < 32; i++) {
      byte[] r2 = Arrays.copyOf(r, r.length);
      r2[i] = (byte) (r2[i] + 1);
      ecdsaSignature = ECDSASignature.fromComponents(r2, s, v);
      try {
        byte[] ecdsaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
        Assert.assertNotEquals(ByteArray.toHexString(ecdsaAddress), ByteArray.toHexString(address));
      } catch (SignatureException e) {
        Assert.assertEquals(e.getMessage(), "Could not parse pub key");
      }
    }

    for (int i = 0; i < 32; i++) {
      byte[] s2 = Arrays.copyOf(s, s.length);
      s2[i] = (byte) (s2[i] + 1);
      ecdsaSignature = ECDSASignature.fromComponents(r, s2, v);

      byte[] ecdsaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
      Assert.assertNotEquals(ByteArray.toHexString(ecdsaAddress), ByteArray.toHexString(address));
    }

    for (int i = 27; i < 60; i++) {
      byte v2 = (byte) (i);
      if (v2 == v) {
        continue;
      }
      ecdsaSignature = ECDSASignature.fromComponents(r, s, v2);
      try {
        byte[] ecdsaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
        Assert.assertNotEquals(ByteArray.toHexString(ecdsaAddress), ByteArray.toHexString(address));
      } catch (Exception e) {
        Assert.assertTrue(e instanceof SignatureException);
      }
    }

    ecdsaSignature = ECDSASignature.fromComponents(r, s, v);
    byte[] ecdsaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
    Assert.assertArrayEquals(ecdsaAddress, address);

  }

  @Test
  public void testSignatureMalleability() throws SignatureException {
    ECKeyV2 key = new ECKeyV2();
    byte[] randomBytes = new byte[128];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);
    ECDSASignature signature = key.sign(msgHash);

    byte[] pubKeyBytes = ECKeyV2.signatureToKeyBytes(msgHash, signature.toBase64());
    Assert.assertArrayEquals(pubKeyBytes, key.getPubKey());

    BigInteger flipS = ECKeyV2.CURVE.getN().subtract(signature.s);
    Assert.assertTrue(flipS.compareTo(ECKey.HALF_CURVE_ORDER) >= 0);

    byte[] flipPubKeyBytes = ECKeyV2.signatureToKeyBytes(msgHash,
        ECDSASignature.fromComponents(signature.r.toByteArray(), flipS.toByteArray(), signature.v)
            .toBase64());
    Assert.assertNotEquals(ByteArray.toHexString(flipPubKeyBytes),
        ByteArray.toHexString(key.getPubKey()));

    byte flipV;
    if (signature.v <= 28) {
      flipV = signature.v == 27 ? (byte) 28 : (byte) 27;
    } else {
      flipV = signature.v == 29 ? (byte) 30 : (byte) 29;
    }

    flipPubKeyBytes = ECKeyV2.signatureToKeyBytes(msgHash,
        ECDSASignature.fromComponents(signature.r.toByteArray(), flipS.toByteArray(), flipV)
            .toBase64());
    Assert.assertArrayEquals(flipPubKeyBytes, key.getPubKey());
  }

  // @Test
  // public void testPrivateKeyBytes() throws SignatureException {
  //   ECKeyV2 ecKeyV2;
  //   byte[] privateKey;
  //   assertInvalidPrivateKey(null);
  //   assertInvalidPrivateKey(new byte[0]);
  //   assertInvalidPrivateKey(new byte[1]);
  //   assertInvalidPrivateKey(new byte[32]);
  //   assertInvalidPrivateKey(ECKey.CURVE.getN().toByteArray());
  //   assertInvalidPrivateKey(ECKey.CURVE.getN().add(BigInteger.ONE).toByteArray());
  //
  //   privateKey = new byte[]{1};
  //   ecKeyV2 = new ECKeyV2(privateKey);
  //   Assert.assertEquals(0, ecKeyV2.getPrivKey().compareTo(BigInteger.ONE));
  //
  //   BigInteger nSubOne = ECKey.CURVE.getN().subtract(BigInteger.ONE);
  //   privateKey = nSubOne.toByteArray();
  //   ecKeyV2 = new ECKeyV2(privateKey);
  //   Assert.assertEquals(0, ecKeyV2.getPrivKey().compareTo(nSubOne));
  // }

  private void assertInvalidPrivateKey(byte[] privateKey)
      throws SignatureException {
    try {
      new ECKeyV2(privateKey);
      fail("Should throw IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      Assert.assertTrue(e.getMessage().contains("Invalid private key"));
    }
  }

  @Test
  public void testSignHash() throws SignatureException {
    ECKeyV2 key = new ECKeyV2();
    final String EXPECTED_ERROR_MESSAGE = "Hash must be 32 bytes array.";

    try {
      key.signHash(null);
      fail("Should throw IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      Assert.assertEquals(EXPECTED_ERROR_MESSAGE, e.getMessage());
    }

    try {
      key.signHash(new byte[0]);
      fail("Should throw IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      Assert.assertEquals(EXPECTED_ERROR_MESSAGE, e.getMessage());
    }

    for (int i = 1; i < 32; i++) {
      try {
        key.signHash(new byte[i]);
        fail("Should throw IllegalArgumentException for length " + i);
      } catch (IllegalArgumentException e) {
        Assert.assertEquals(EXPECTED_ERROR_MESSAGE, e.getMessage());
      }
    }

    try {
      key.signHash(new byte[33]);
      fail("Should throw IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      Assert.assertEquals(EXPECTED_ERROR_MESSAGE, e.getMessage());
    }

    key.signHash(new byte[32]);
  }

  @Ignore
  @Test
  public void ecKeySignBench() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    privString = PublicMethod.getRandomPrivateKey();
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    SignInterface ecKey = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    String signature = ecKey.signHash(msgHash);
    int iterations = 10000;
    // warm up
    for (int i = 0; i < iterations; i++) {
      ecKey.signHash(msgHash);
    }
    long startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ecKey.signHash(msgHash);
    }
    long endTime = System.nanoTime();
    long durationNs = endTime - startTime;
    long nsPerIteration = durationNs / iterations;
    logger.info("ECKey sign cost: " + nsPerIteration + "ns per call");


    SignInterface ecKeyV2 = ECKeyV2.fromPrivate(ByteArray.fromHexString(privString));
    String signatureV2 = ecKeyV2.signHash(msgHash);
    Assert.assertEquals(signature, signatureV2);

    // warm up
    for (int i = 0; i < iterations; i++) {
      ecKeyV2.signHash(msgHash);
    }
    startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ecKeyV2.signHash(msgHash);
    }
    endTime = System.nanoTime();
    durationNs = endTime - startTime;
    long nsPerIterationV2 = durationNs / iterations;
    logger.info("ECKeyV2 sign cost: " + nsPerIterationV2 + "ns per call");
    logger.info("ECKeyV1/ECKeyV2: " + nsPerIteration / nsPerIterationV2);
  }

  @Ignore
  @Test
  public void ecKeyVerifyBench() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    privString = PublicMethod.getRandomPrivateKey();
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);

    SignInterface ecKey = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    String signature = ecKey.signHash(msgHash);
    byte[] ecKeyAddress = ECKey.signatureToAddress(msgHash, signature);
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
    logger.info("ECKey verify cost: " + nsPerIteration + "ns per call");


    SignInterface ecKeyV2 = ECKeyV2.fromPrivate(ByteArray.fromHexString(privString));
    String signatureV2 = ecKeyV2.signHash(msgHash);
    Assert.assertEquals(signature, signatureV2);
    byte[] ecKeyV2Address = ECKeyV2.signatureToAddress(msgHash, signatureV2);
    Assert.assertArrayEquals(ecKeyAddress, ecKeyV2Address);

    // warm up
    for (int i = 0; i < iterations; i++) {
      ECKeyV2.signatureToAddress(msgHash, signatureV2);
    }
    startTime = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      ECKeyV2.signatureToAddress(msgHash, signatureV2);
    }
    endTime = System.nanoTime();
    durationNs = endTime - startTime;
    long nsPerIterationV2 = durationNs / iterations;
    logger.info("ECKeyV2 verify cost: " + nsPerIterationV2 + "ns per call");
    logger.info("ECKeyV1/ECKeyV2: " + nsPerIteration / nsPerIterationV2);
  }
}
