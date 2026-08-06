package org.tron.common.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Assume;
import org.junit.Test;
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
  public void shouldKeepJavaVerificationDisabledByDefault() {
    assertFalse(SignUtils.isUseNativeSecp256k1());
  }

  @Test
  public void shouldRecoverSamePublicKeyAsJava() throws SignatureException {
    requireNativeLibrary();
    ECDSASignature signature = KEY.sign(MESSAGE_HASH);

    assertArrayEquals(
        ECKey.signatureToKeyBytes(MESSAGE_HASH, signature),
        NativeSecp256k1.signatureToKeyBytes(MESSAGE_HASH, signature));
    assertArrayEquals(
        ECKey.signatureToAddress(MESSAGE_HASH, signature),
        NativeSecp256k1.signatureToAddress(MESSAGE_HASH, signature));
  }

  @Test
  public void shouldProduceSameDeterministicSignatureAsJava() throws SignatureException {
    requireNativeLibrary();

    ECDSASignature javaSignature = KEY.sign(MESSAGE_HASH);
    ECDSASignature nativeSignature =
        NativeSecp256k1.sign(MESSAGE_HASH, KEY.getPrivateKey());

    assertArrayEquals(javaSignature.toByteArray(), nativeSignature.toByteArray());
    assertEquals(javaSignature.toBase64(), nativeSignature.toBase64());
  }

  @Test
  public void shouldConstructFromPrivateKeyAndUseNativeOperations() throws SignatureException {
    requireNativeLibrary();
    NativeSecp256k1 nativeKey = new NativeSecp256k1(KEY.getPrivateKey());

    assertArrayEquals(KEY.getPrivateKey(), nativeKey.getPrivateKey());
    assertArrayEquals(KEY.getPubKey(), nativeKey.getPubKey());
    assertArrayEquals(KEY.getAddress(), nativeKey.getAddress());
    assertArrayEquals(KEY.sign(MESSAGE_HASH).toByteArray(),
        nativeKey.sign(MESSAGE_HASH).toByteArray());
    assertEquals(KEY.signHash(MESSAGE_HASH), nativeKey.signHash(MESSAGE_HASH));
  }

  @Test
  public void shouldGenerateCompatibleKeyPairsWithBothConstructors() throws SignatureException {
    requireNativeLibrary();
    assertCompatibleKeyPair(new NativeSecp256k1());
    assertCompatibleKeyPair(new NativeSecp256k1(new SecureRandom()));
  }

  @Test
  public void shouldRejectInvalidConstructorArguments() throws SignatureException {
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
  public void shouldCrossVerifyJavaAndNativeSignatures() throws SignatureException {
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
      assertArrayEquals(javaSignature.toByteArray(), nativeSignature.toByteArray());
    }
  }

  @Test
  public void shouldRecoverBase64SignatureWithTrailingBytes() throws SignatureException {
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
  public void shouldPreserveHighSSignatureRecovery() throws SignatureException {
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
  public void shouldRouteVerificationThroughConfiguredImplementation()
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
  public void shouldRejectInvalidRecoveryHeader() {
    requireNativeLibrary();
    ECDSASignature valid = KEY.sign(MESSAGE_HASH);
    ECDSASignature invalid = ECDSASignature.fromComponents(
        valid.r.toByteArray(), valid.s.toByteArray(), (byte) 26);

    try {
      NativeSecp256k1.signatureToAddress(MESSAGE_HASH, invalid);
      fail("Expected SignatureException");
    } catch (SignatureException e) {
      assertTrue(e.getMessage().contains("Header byte out of range"));
    }
  }

  @Test
  public void shouldRejectOversizedSignatureComponentsWithoutTruncating() {
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
