package org.tron.common.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mockStatic;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Assume;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.slf4j.LoggerFactory;
import org.tron.common.crypto.ECKey.ECDSASignature;

public class NativeSecp256k1Test {

  private static final byte[] MESSAGE_HASH =
      Hash.sha3("native verification".getBytes(StandardCharsets.UTF_8));
  private static final ECKey KEY = ECKey.fromPrivate(BigInteger.TEN);

  @After
  public void resetVerificationMode() {
    SignUtils.setUseNativeSecp256k1(false);
  }

  @Test
  public void testNativeDisabledByDefault() {
    assertFalse(SignUtils.isUseNativeSecp256k1());
  }

  @Test
  public void testUnavailableNativeFallback() {
    Logger logger = (Logger) LoggerFactory.getLogger("crypto");
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      SignUtils.setUseNativeSecp256k1(true, false);

      assertFalse(SignUtils.isUseNativeSecp256k1());
      assertTrue(appender.list.stream().anyMatch(event ->
          event.getLevel() == Level.WARN
              && event.getFormattedMessage().contains("crypto.useNativeSecp256k1=true")
              && event.getFormattedMessage().contains("falling back to ECKey")));
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  @Test
  public void testPublicKeyRecovery() throws SignatureException {
    requireNativeLibrary();
    ECDSASignature signature = KEY.sign(MESSAGE_HASH);

    assertArrayEquals(
        ECKey.signatureToKeyBytes(MESSAGE_HASH, signature),
        NativeSecp256k1.signatureToKeyBytes(MESSAGE_HASH, signature));
  }

  @Test
  public void testCompressedHeaderRecovery()
      throws SignatureException {
    requireNativeLibrary();
    ECDSASignature signature = KEY.sign(MESSAGE_HASH);
    ECDSASignature compressedHeaderSignature = ECDSASignature.fromComponents(
        signature.r.toByteArray(), signature.s.toByteArray(), (byte) (signature.v + 4));

    byte[] javaPublicKey = ECKey.signatureToKeyBytes(MESSAGE_HASH, compressedHeaderSignature);
    assertEquals(65, javaPublicKey.length);
    assertArrayEquals(javaPublicKey,
        NativeSecp256k1.signatureToKeyBytes(MESSAGE_HASH, compressedHeaderSignature));
  }

  @Test
  public void testShortPrivateKeySigning() throws SignatureException {
    requireNativeLibrary();
    byte[] privateKey = {(byte) 0x0a};
    byte[] originalPrivateKey = Arrays.copyOf(privateKey, privateKey.length);

    ECDSASignature nativeSignature = NativeSecp256k1.sign(MESSAGE_HASH, privateKey);

    assertArrayEquals(KEY.sign(MESSAGE_HASH).toByteArray(), nativeSignature.toByteArray());
    assertArrayEquals(originalPrivateKey, privateKey);
  }

  @Test
  public void testBigIntegerPrivateKeySigning() throws SignatureException {
    requireNativeLibrary();
    BigInteger privateKeyValue = ECKey.CURVE.getN().subtract(BigInteger.ONE);
    byte[] privateKey = privateKeyValue.toByteArray();
    ECKey key = ECKey.fromPrivate(privateKeyValue);

    assertEquals(33, privateKey.length);
    assertArrayEquals(key.sign(MESSAGE_HASH).toByteArray(),
        NativeSecp256k1.sign(MESSAGE_HASH, privateKey).toByteArray());
  }

  @Test
  public void testInvalidPrivateKeySigning() throws SignatureException {
    requireNativeLibrary();

    try {
      NativeSecp256k1.sign(MESSAGE_HASH, new byte[]{0});
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("outside the secp256k1 range"));
    }
  }

  @Test
  public void testNativeKeyOperations() throws SignatureException {
    requireNativeLibrary();
    NativeSecp256k1 nativeKey = new NativeSecp256k1(KEY.getPrivateKey());

    assertArrayEquals(KEY.getPrivateKey(), nativeKey.getPrivateKey());
    assertArrayEquals(KEY.getPubKey(), nativeKey.getPubKey());
    assertArrayEquals(KEY.getAddress(), nativeKey.getAddress());
    assertArrayEquals(KEY.sign(MESSAGE_HASH).toByteArray(),
        nativeKey.sign(MESSAGE_HASH).toByteArray());
  }

  @Test
  public void testKeyPairConstructors() throws SignatureException {
    requireNativeLibrary();
    assertCompatibleKeyPair(new NativeSecp256k1());
    assertCompatibleKeyPair(new NativeSecp256k1(new SecureRandom()));
  }

  @Test
  public void testInvalidConstructorArguments() throws SignatureException {
    requireNativeLibrary();
    assertInvalidPrivateKey(null);
    assertInvalidPrivateKey(new byte[0]);
    assertInvalidPrivateKey(new byte[32]);
    assertInvalidPrivateKey(new byte[33]);
    assertInvalidPrivateKey(ECKey.CURVE.getN().toByteArray());

    try {
      new NativeSecp256k1((SecureRandom) null);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("must not be null"));
    }
  }

  @Test
  public void testJavaNativeCrossCompatibility() throws SignatureException {
    requireNativeLibrary();
    for (int i = 1; i <= 32; i++) {
      ECKey key = ECKey.fromPrivate(BigInteger.valueOf(i));
      byte[] messageHash = Hash.sha3(
          ("cross verification " + i).getBytes(StandardCharsets.UTF_8));
      ECDSASignature javaSignature = key.sign(messageHash);
      ECDSASignature nativeSignature =
          NativeSecp256k1.sign(messageHash, key.getPrivateKey());

      assertArrayEquals(
          key.getAddress(), NativeSecp256k1.signatureToAddress(messageHash, javaSignature));
      assertArrayEquals(
          key.getAddress(), ECKey.signatureToAddress(messageHash, nativeSignature));
      assertEquals(javaSignature.toBase64(), nativeSignature.toBase64());
    }
  }

  @Test
  public void testBase64TrailingBytesRecovery() throws SignatureException {
    requireNativeLibrary();
    ECDSASignature signature = KEY.sign(MESSAGE_HASH);
    byte[] encoded = Base64.decode(signature.toBase64());
    byte[] padded = Arrays.copyOf(encoded, encoded.length + 3);
    String paddedBase64 = new String(Base64.encode(padded), StandardCharsets.US_ASCII);

    assertArrayEquals(
        ECKey.signatureToAddress(MESSAGE_HASH, paddedBase64),
        NativeSecp256k1.signatureToAddress(MESSAGE_HASH, paddedBase64));
  }

  @Test
  public void testHighSRecovery() throws SignatureException {
    requireNativeLibrary();
    ECDSASignature signature = KEY.sign(MESSAGE_HASH);
    BigInteger highS = ECKey.CURVE.getN().subtract(signature.s);
    byte flippedV = signature.v == 27 ? (byte) 28 : (byte) 27;
    ECDSASignature highSSignature = ECDSASignature.fromComponents(
        signature.r.toByteArray(), highS.toByteArray(), flippedV);

    assertArrayEquals(
        ECKey.signatureToAddress(MESSAGE_HASH, highSSignature),
        NativeSecp256k1.signatureToAddress(MESSAGE_HASH, highSSignature));
  }

  @Test
  public void testScalarBoundaryRecovery() {
    requireNativeLibrary();
    BigInteger curveOrder = ECKey.CURVE.getN();
    BigInteger[] boundaryValues = {
        BigInteger.ZERO,
        BigInteger.ONE,
        curveOrder.subtract(BigInteger.ONE),
        curveOrder,
        curveOrder.add(BigInteger.ONE)
    };

    for (BigInteger r : boundaryValues) {
      for (BigInteger s : boundaryValues) {
        for (byte header = 27; header <= 34; header++) {
          assertSameRecoveryOutcome(r, s, header);
        }
      }
    }
  }

  @Test
  public void testInfinityRecovery() throws SignatureException {
    requireNativeLibrary();
    byte[] unitHash = new byte[32];
    unitHash[unitHash.length - 1] = 1;
    BigInteger generatorX = ECKey.CURVE.getG().getXCoord().toBigInteger();
    byte header = ECKey.CURVE.getG().getYCoord().toBigInteger().testBit(0)
        ? (byte) 28 : (byte) 27;
    ECDSASignature signature = new ECDSASignature(generatorX, BigInteger.ONE);
    signature.v = header;

    assertArrayEquals(
        ECKey.signatureToKeyBytes(unitHash, signature),
        NativeSecp256k1.signatureToKeyBytes(unitHash, signature));
  }

  @Test
  public void testConfiguredNativeRouting()
      throws SignatureException {
    String signature = KEY.signHash(MESSAGE_HASH);
    byte[] nativeAddress = {1, 2, 3};

    try (MockedStatic<NativeSecp256k1> nativeSecp256k1 =
        mockStatic(NativeSecp256k1.class)) {
      nativeSecp256k1.when(NativeSecp256k1::isAvailable).thenReturn(true);
      nativeSecp256k1.when(
          () -> NativeSecp256k1.signatureToAddress(MESSAGE_HASH, signature))
          .thenReturn(nativeAddress);

      SignUtils.setUseNativeSecp256k1(true);

      assertTrue(SignUtils.isUseNativeSecp256k1());
      assertArrayEquals(nativeAddress,
          SignUtils.signatureToAddress(MESSAGE_HASH, signature, true));
      nativeSecp256k1.verify(
          () -> NativeSecp256k1.signatureToAddress(MESSAGE_HASH, signature));
    }
  }

  @Test
  public void testConfiguredNativeAddressCompatibility()
      throws SignatureException {
    requireNativeLibrary();
    String signature = KEY.signHash(MESSAGE_HASH);

    SignUtils.setUseNativeSecp256k1(true);

    assertTrue(SignUtils.isUseNativeSecp256k1());
    assertArrayEquals(
        ECKey.signatureToAddress(MESSAGE_HASH, signature),
        SignUtils.signatureToAddress(MESSAGE_HASH, signature, true));
  }

  @Test
  public void testInvalidRecoveryHeaders() {
    requireNativeLibrary();
    ECDSASignature valid = KEY.sign(MESSAGE_HASH);

    for (byte header : new byte[]{26, 35}) {
      ECDSASignature invalid = ECDSASignature.fromComponents(
          valid.r.toByteArray(), valid.s.toByteArray(), header);
      try {
        NativeSecp256k1.signatureToAddress(MESSAGE_HASH, invalid);
        fail("Expected SignatureException");
      } catch (SignatureException e) {
        assertTrue(e.getMessage().contains("Header byte out of range"));
      }
    }
  }

  @Test
  public void testOversizedSignatureComponents() {
    requireNativeLibrary();
    ECDSASignature valid = KEY.sign(MESSAGE_HASH);
    BigInteger oversizedR = BigInteger.ONE.shiftLeft(256).add(valid.r);
    ECDSASignature invalid = ECDSASignature.fromComponents(
        oversizedR.toByteArray(), valid.s.toByteArray(), valid.v);

    try {
      NativeSecp256k1.signatureToAddress(MESSAGE_HASH, invalid);
      fail("Expected SignatureException");
    } catch (SignatureException e) {
      assertTrue(e.getMessage().contains("unsigned 32-byte integers"));
    }
  }

  private static void requireNativeLibrary() {
    Assume.assumeTrue("Native secp256k1 library is unavailable",
        NativeSecp256k1.isAvailable());
  }

  private static void assertSameRecoveryOutcome(BigInteger r, BigInteger s, byte header) {
    ECDSASignature signature = new ECDSASignature(r, s);
    signature.v = header;
    String message = "Recovery mismatch for r=" + r + ", s=" + s + ", v=" + header;

    byte[] javaPublicKey;
    try {
      javaPublicKey = ECKey.signatureToKeyBytes(MESSAGE_HASH, signature);
    } catch (Exception javaFailure) {
      try {
        NativeSecp256k1.signatureToKeyBytes(MESSAGE_HASH, signature);
        fail(message + ": Java rejected but native recovered");
        return;
      } catch (Exception nativeFailure) {
        assertEquals(message, javaFailure.getClass(), nativeFailure.getClass());
        return;
      }
    }

    try {
      assertArrayEquals(message, javaPublicKey,
          NativeSecp256k1.signatureToKeyBytes(MESSAGE_HASH, signature));
    } catch (Exception nativeFailure) {
      fail(message + ": Java recovered but native rejected: " + nativeFailure.getMessage());
    }
  }

  private static void assertCompatibleKeyPair(NativeSecp256k1 nativeKey) {
    ECKey javaKey = ECKey.fromPrivate(nativeKey.getPrivateKey());

    assertArrayEquals(javaKey.getPubKey(), nativeKey.getPubKey());
    assertArrayEquals(javaKey.getAddress(), nativeKey.getAddress());
    assertArrayEquals(javaKey.sign(MESSAGE_HASH).toByteArray(),
        nativeKey.sign(MESSAGE_HASH).toByteArray());
  }

  private static void assertInvalidPrivateKey(byte[] privateKey) throws SignatureException {
    try {
      new NativeSecp256k1(privateKey);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("privateKey argument"));
    }
  }
}
