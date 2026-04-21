package org.tron.common.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.tron.common.utils.client.utils.AbiUtil.generateOccupationConstantPrivateKey;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.Wallet;

/**
 * The reason the test case uses the private key plaintext is to ensure that,
 * after the ECkey tool or algorithm is upgraded,
 * the upgraded differences can be verified.
 */
@Slf4j
public class ECKeyTest {

  // For safety reasons, test with a placeholder private key
  private String privString = generateOccupationConstantPrivateKey();
  private BigInteger privateKey = new BigInteger(privString, 16);

  private String pubString = "04e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e62"
      + "5529392df7fa514bdd65a2003f6619567d79bee89830e63e932dbd42362d34";
  private String compressedPubString =
      "02e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e";
  private byte[] pubKey = Hex.decode(pubString);
  private byte[] compressedPubKey = Hex.decode(compressedPubString);
  private String address = "2e988a386a799f506693793c6a5af6b54dfaabfb";
  String eventSign = "eventBytesL(address,bytes,bytes32,uint256,string)";

  @Test
  public void testSha3() {
    assertNotEquals(Hash.sha3(eventSign.getBytes()).length, 0);
  }

  @Test
  public void testHashCode() {
    assertEquals(-827927068, ECKey.fromPrivate(privateKey).hashCode());
  }

  @Test
  public void testECKey() {
    ECKey key = new ECKey();
    assertTrue(key.isPubKeyCanonical());
    assertNotNull(key.getPubKey());
    assertNotNull(key.getPrivKeyBytes());
    logger.info(Hex.toHexString(key.getPrivKeyBytes()) + " :Generated privkey");
    logger.info(Hex.toHexString(key.getPubKey()) + " :Generated pubkey");
  }

  @Test
  public void testFromPrivateKey() {
    ECKey key = ECKey.fromPrivate(privateKey);
    assertTrue(key.isPubKeyCanonical());
    assertTrue(key.hasPrivKey());
    assertArrayEquals(pubKey, key.getPubKey());

    key =  ECKey.fromPrivate((byte[]) null);
    assertNull(key);
    key = ECKey.fromPrivate(new byte[0]);
    assertNull(key);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testPrivatePublicKeyBytesNoArg() {
    new ECKey((BigInteger) null, null);
    fail("Expecting an IllegalArgumentException for using only null-parameters");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testInvalidPrivateKey() throws Exception {
    new ECKey(Security.getProvider("SunEC"),
        KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(),
        ECKey.fromPublicOnly(pubKey).getPubKeyPoint());
    fail("Expecting an IllegalArgumentException for using an non EC private key");
  }

  @Test
  public void testIsPubKeyOnly() {
    ECKey key = ECKey.fromPublicOnly(pubKey);
    assertTrue(key.isPubKeyCanonical());
    assertTrue(key.isPubKeyOnly());
    assertArrayEquals(key.getPubKey(), pubKey);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSignIncorrectInputSize() {
    ECKey key = new ECKey();
    String message = "The quick brown fox jumps over the lazy dog.";
    ECDSASignature sig = key.doSign(message.getBytes());
    fail("Expecting an IllegalArgumentException for a non 32-byte input");
  }

  @Test(expected = SignatureException.class)
  public void testBadBase64Sig() throws SignatureException {
    byte[] messageHash = new byte[32];
    ECKey.signatureToKey(messageHash, "This is not valid Base64!");
    fail("Expecting a SignatureException for invalid Base64");
  }

  @Test(expected = SignatureException.class)
  public void testInvalidSignatureLength() throws SignatureException {
    byte[] messageHash = new byte[32];
    ECKey.signatureToKey(messageHash, "abcdefg");
    fail("Expecting a SignatureException for invalid signature length");
  }

  @Test
  public void testPublicKeyFromPrivate() {
    byte[] pubFromPriv = ECKey.publicKeyFromPrivate(privateKey, false);
    assertArrayEquals(pubKey, pubFromPriv);
  }

  @Test
  public void testPublicKeyFromPrivateCompressed() {
    byte[] pubFromPriv = ECKey.publicKeyFromPrivate(privateKey, true);
    assertArrayEquals(compressedPubKey, pubFromPriv);
  }

  @Test
  public void testGetAddress() {
    ECKey key = ECKey.fromPublicOnly(pubKey);
    // Addresses are prefixed with a constant.
    byte[] prefixedAddress = key.getAddress();
    byte[] unprefixedAddress = Arrays.copyOfRange(key.getAddress(), 1, prefixedAddress.length);
    assertArrayEquals(Hex.decode(address), unprefixedAddress);
    assertEquals(Wallet.getAddressPreFixByte(), prefixedAddress[0]);
  }

  @Test
  public void testGetAddressFromPrivateKey() {
    ECKey key = ECKey.fromPrivate(privateKey);
    // Addresses are prefixed with a constant.
    byte[] prefixedAddress = key.getAddress();
    byte[] unprefixedAddress = Arrays.copyOfRange(key.getAddress(), 1, prefixedAddress.length);
    assertArrayEquals(Hex.decode(address), unprefixedAddress);
    assertEquals(Wallet.getAddressPreFixByte(), prefixedAddress[0]);
  }

  @Test
  public void testToString() {
    ECKey key = ECKey.fromPrivate(BigInteger.TEN); // An example private key.
    assertEquals("pub:04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba42"
        + "5419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7", key.toString());
  }

  @Test
  public void testIsPubKeyCanonicalCorect() {
    // Test correct prefix 4, right length 65
    byte[] canonicalPubkey1 = new byte[65];
    canonicalPubkey1[0] = 0x04;
    assertTrue(ECKey.isPubKeyCanonical(canonicalPubkey1));
    // Test correct prefix 2, right length 33
    byte[] canonicalPubkey2 = new byte[33];
    canonicalPubkey2[0] = 0x02;
    assertTrue(ECKey.isPubKeyCanonical(canonicalPubkey2));
    // Test correct prefix 3, right length 33
    byte[] canonicalPubkey3 = new byte[33];
    canonicalPubkey3[0] = 0x03;
    assertTrue(ECKey.isPubKeyCanonical(canonicalPubkey3));
  }

  @Test
  public void testIsPubKeyCanonicalWrongLength() {
    // Test correct prefix 4, but wrong length !65
    byte[] nonCanonicalPubkey1 = new byte[64];
    nonCanonicalPubkey1[0] = 0x04;
    assertFalse(ECKey.isPubKeyCanonical(nonCanonicalPubkey1));
    // Test correct prefix 2, but wrong length !33
    byte[] nonCanonicalPubkey2 = new byte[32];
    nonCanonicalPubkey2[0] = 0x02;
    assertFalse(ECKey.isPubKeyCanonical(nonCanonicalPubkey2));
    // Test correct prefix 3, but wrong length !33
    byte[] nonCanonicalPubkey3 = new byte[32];
    nonCanonicalPubkey3[0] = 0x03;
    assertFalse(ECKey.isPubKeyCanonical(nonCanonicalPubkey3));
  }

  @Test
  public void testIsPubKeyCanonicalWrongPrefix() {
    // Test wrong prefix 4, right length 65
    byte[] nonCanonicalPubkey4 = new byte[65];
    assertFalse(ECKey.isPubKeyCanonical(nonCanonicalPubkey4));
    // Test wrong prefix 2, right length 33
    byte[] nonCanonicalPubkey5 = new byte[33];
    assertFalse(ECKey.isPubKeyCanonical(nonCanonicalPubkey5));
    // Test wrong prefix 3, right length 33
    byte[] nonCanonicalPubkey6 = new byte[33];
    assertFalse(ECKey.isPubKeyCanonical(nonCanonicalPubkey6));
  }

  @Test
  public void testGetPrivKeyBytes() {
    ECKey key = new ECKey();
    assertNotNull(key.getPrivKeyBytes());
    assertEquals(32, key.getPrivKeyBytes().length);
  }

  @Test
  public void testEqualsObject() {
    ECKey key0 = new ECKey();
    ECKey key1 = ECKey.fromPrivate(privateKey);
    ECKey key2 = ECKey.fromPrivate(privateKey);

    assertFalse(key0.equals(key1));
    assertTrue(key1.equals(key1));
    assertTrue(key1.equals(key2));
  }

  @Test
  public void testSignatureMalleability() throws SignatureException {
    ECKey key = new ECKey();
    byte[] randomBytes = new byte[128];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(randomBytes);
    byte[] msgHash = Sha256Hash.hash(true, randomBytes);
    ECDSASignature signature = key.sign(msgHash);

    byte[] pubKeyBytes = ECKey.signatureToKeyBytes(msgHash, signature.toBase64());
    Assert.assertArrayEquals(pubKeyBytes, key.getPubKey());

    Assert.assertTrue(signature.s.compareTo(ECKey.HALF_CURVE_ORDER) <= 0);
    BigInteger flipS = ECKey.CURVE.getN().subtract(signature.s);
    Assert.assertTrue(flipS.compareTo(ECKey.HALF_CURVE_ORDER) > 0);

    byte[] flipPubKeyBytes = ECKey.signatureToKeyBytes(msgHash,
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

    flipPubKeyBytes = ECKey.signatureToKeyBytes(msgHash,
        ECDSASignature.fromComponents(signature.r.toByteArray(), flipS.toByteArray(), flipV)
            .toBase64());
    Assert.assertArrayEquals(flipPubKeyBytes, key.getPubKey());
  }

  @Test
  public void testNodeId() {
    ECKey key = ECKey.fromPublicOnly(pubKey);

    assertEquals(key, ECKey.fromNodeId(key.getNodeId()));
  }

  /**
   * Regression timing test for block #81993268 missed-block incident.
   *
   * <p>tx 73350db... contained a signature whose verification was pathologically slow on x86
   * (reported >8 s), exceeding the 3-second block-production slot and causing a missed block.
   * This test benchmarks the offending (r, s) pair so the cost is visible in CI logs.
   */
  @Test
  public void testSignatureVerificationTimingBlock81993268() throws SignatureException {
    byte[] txHash = Hex.decode(
        "73350db08350056f128734ec26444ea549299256ea99e0aaab7f5ad60d0d552a");
    byte[] r = Hex.decode(
        "6f9ef9d226dc87bceb571c859614fa7dcdbe0be6e1dfea54fb99cb9970fa09af");
    byte[] s = Hex.decode(
        "91a945e3b0eb1eea559c89cc4bd16932bfabcf0e63a0e0848fbb7fa0db4dcfd6");

    // v=0x00 on TronScan means recId 0 → header byte 27 (0x1B)
    ECDSASignature sig = ECDSASignature.fromComponents(r, s, (byte) 27);
    int iterations = 10;
    long totalNs = 0;
    long maxNs = 0;

    for (int i = 0; i < iterations; i++) {
      byte[] hash = new byte[32];
      new java.util.Random().nextBytes(hash);
      ECKey.signatureToAddress(hash, sig);
    }

    for (int i = 0; i < iterations; i++) {
      long start = System.nanoTime();
      try {
        ECKey.signatureToAddress(txHash, sig);
      } catch (SignatureException e) {
        // ignored
      }
      long elapsed = System.nanoTime() - start;
      totalNs += elapsed;
      if (elapsed > maxNs) {
        maxNs = elapsed;
      }
    }
    long avgMs = totalNs / iterations / 1_000;
    long maxMs = maxNs / 1_000;
    logger.info("block81993268 sig recovery {}: avg={}us max={}us", iterations, avgMs, maxMs);
    System.out.printf("block81993268 sig recovery x%d: avg=%dus max=%dus%n",
        iterations, avgMs, maxMs);
  }

  @Test
  public void testSignatureVerificationTimingRandom() throws SignatureException {
    int iterations = 1000;
    long maxMs = 0;
    long totalMs = 0;

    for (int i = 0; i < iterations; i++) {
      ECKey key = new ECKey();
      byte[] hash = new byte[32];
      new java.util.Random().nextBytes(hash);
      ECDSASignature sig = key.sign(hash);
      ECKeyV2.signatureToAddress(hash, sig);
    }

    for (int i = 0; i < iterations; i++) {
      ECKey key = new ECKey();
      byte[] hash = new byte[32];
      new java.util.Random().nextBytes(hash);
      ECDSASignature sig = key.sign(hash);

      long start = System.nanoTime();
      ECKey.signatureToAddress(hash, sig);
      long elapsedMs = (System.nanoTime() - start) / 1_000;

      totalMs += elapsedMs;
      if (elapsedMs > maxMs) {
        maxMs = elapsedMs;
      }
//      assertTrue("Iteration " + i + " took " + elapsedMs + "us", elapsedMs < 1000);
    }

    logger.info("Random sig verification {}: avg={}us max={}us",
        iterations, totalMs / iterations, maxMs);
    System.out.printf("Random sig verification %d: avg=%dus max=%dus%n",
        iterations, totalMs / iterations, maxMs);
  }

}
