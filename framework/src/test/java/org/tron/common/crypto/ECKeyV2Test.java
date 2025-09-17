package org.tron.common.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.PublicMethod;
import org.tron.common.utils.Sha256Hash;

@Slf4j
public class ECKeyV2Test {

  private String privString;
  private SecureRandom secureRandom = new SecureRandom();

  @Test
  public void testECKeyV2() throws Exception {
    ECKey ecKey = new ECKey();
    ECKeyV2 ecKeyV2 = ECKeyV2.fromECKey(ecKey);
    Assert.assertArrayEquals(ecKey.getPubKey(), ecKey.getPubKey());
    Assert.assertArrayEquals(ecKey.getAddress(), ecKeyV2.getAddress());

    ecKeyV2 = new ECKeyV2();
    ecKey = ECKey.fromPrivate(ecKeyV2.getPrivateKey());
    assert ecKey != null;
    Assert.assertArrayEquals(ecKey.getPubKey(), ecKey.getPubKey());
    Assert.assertArrayEquals(ecKey.getAddress(), ecKeyV2.getAddress());

    ecKey = new ECKey();
    ecKeyV2 = ECKeyV2.fromPrivate(ecKey.getPrivateKey());
    Assert.assertArrayEquals(ecKey.getPubKey(), ecKey.getPubKey());
    assert ecKeyV2 != null;
    Assert.assertArrayEquals(ecKey.getAddress(), ecKeyV2.getAddress());
  }

  @Test
  public void testSignature() throws SignatureException {
    byte[] randomBytes = new byte[128];
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);
    logger.info("msgHash: " + ByteArray.toHexString(msgHash));

    privString = PublicMethod.getRandomPrivateKey();
    logger.info("privString: " + privString);
    SignInterface ecKey = ECKey.fromPrivate(ByteArray.fromHexString(privString));
    String signature = ecKey.signHash(msgHash);
    byte[] signatureBytes = ecKey.Base64toBytes(signature);
    logger.info("signature: {}", signature);
    logger.info("signatureBytes: {}", ByteArray.toHexString(signatureBytes));

    SignInterface ecKeyV2 = ECKeyV2.fromPrivate(ByteArray.fromHexString(privString));
    String signatureV2 = ecKeyV2.signHash(msgHash);
    byte[] signatureBytesV2 = ecKeyV2.Base64toBytes(signatureV2);
    logger.info("signatureV2: {}", signatureV2);
    logger.info("signatureBytesV2: {}", ByteArray.toHexString(signatureBytesV2));

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
    logger.info("pubKeyBytes: " + ByteArray.toHexString(pubKeyBytes));
    logger.info("ecKeyV2 pubkey: " + ByteArray.toHexString(ecKeyV2.getPubKey()));
    Assert.assertArrayEquals(pubKeyBytes, ecKeyV2.getPubKey());

    byte[] address = ECKeyV2.signatureToAddress(msgHash, signatureV2);
    logger.info("address: " + ByteArray.toHexString(address));
    logger.info("ecKeyV2 address: " + ByteArray.toHexString(ecKeyV2.getAddress()));
    Assert.assertArrayEquals(address, ecKeyV2.getAddress());

    byte[] ecKeyAddress = ECKey.signatureToAddress(msgHash, signatureV2);
    logger.info("ecKeyAddress: " + ByteArray.toHexString(ecKeyAddress));
    Assert.assertArrayEquals(address, ecKeyAddress);

    ECDSASignature ecdsaSignature = ECDSASignature.parseBase64Signature(signatureV2);
    byte[] ecdaaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
    logger.info("ecdaaAddress: " + ByteArray.toHexString(ecdaaAddress));
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
    logger.info("pubKeyBytes: " + ByteArray.toHexString(pubKeyBytes));
    logger.info("ecKey pubkey: " + ByteArray.toHexString(ecKey.getPubKey()));
    Assert.assertArrayEquals(pubKeyBytes, ecKey.getPubKey());

    byte[] address = ECKeyV2.signatureToAddress(msgHash, signature);
    logger.info("address: " + ByteArray.toHexString(address));
    logger.info("ecKey address: " + ByteArray.toHexString(ecKey.getAddress()));
    Assert.assertArrayEquals(address, ecKey.getAddress());

    byte[] ecKeyAddress = ECKey.signatureToAddress(msgHash, signature);
    logger.info("ecKeyAddress: " + ByteArray.toHexString(ecKeyAddress));
    Assert.assertArrayEquals(address, ecKeyAddress);

    ECDSASignature ecdsaSignature = ECDSASignature.parseBase64Signature(signature);
    byte[] ecdaaAddress = ECKeyV2.signatureToAddress(msgHash, ecdsaSignature);
    logger.info("ecdaaAddress: " + ByteArray.toHexString(ecdaaAddress));
    Assert.assertArrayEquals(address, ecdaaAddress);
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

    BigInteger secp256K1N =
        new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    Assert.assertTrue(signature.s.compareTo(ECKey.HALF_CURVE_ORDER) <= 0);

    BigInteger flipS = secp256K1N.subtract(signature.s);
    Assert.assertTrue(flipS.compareTo(ECKey.HALF_CURVE_ORDER) > 0);

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
