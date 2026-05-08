package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.junit.Before;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

public class FNDSATest {

  private static final FalconParameters PARAMS = FalconParameters.falcon_512;

  private FNDSA keypair;
  private FalconPublicKeyParameters pk;
  private FalconPrivateKeyParameters sk;

  @Before
  public void setUp() {
    AsymmetricCipherKeyPair kp = freshKeyPair();
    pk = (FalconPublicKeyParameters) kp.getPublic();
    sk = (FalconPrivateKeyParameters) kp.getPrivate();
    keypair = new FNDSA(sk.getEncoded(), pk.getH());
  }

  private static AsymmetricCipherKeyPair freshKeyPair() {
    FalconKeyPairGenerator gen = new FalconKeyPairGenerator();
    gen.init(new FalconKeyGenerationParameters(new SecureRandom(), PARAMS));
    return gen.generateKeyPair();
  }

  private byte[] rawSign(byte[] message) {
    FalconSigner signer = new FalconSigner();
    signer.init(true, new ParametersWithRandom(sk, new SecureRandom()));
    try {
      return signer.generateSignature(message);
    } catch (Exception e) {
      throw new AssertionError("failed to sign in test setup", e);
    }
  }

  @Test
  public void schemeAndLengthsMatchFips206Draft() {
    assertEquals(PQScheme.FN_DSA_512, keypair.getScheme());
    assertEquals(FNDSA.PUBLIC_KEY_LENGTH, keypair.getPublicKeyLength());
    assertEquals(FNDSA.SIGNATURE_LENGTH, keypair.getSignatureLength());
    assertEquals(FNDSA.PRIVATE_KEY_LENGTH, keypair.getPrivateKeyLength());
    assertEquals(FNDSA.PUBLIC_KEY_LENGTH, pk.getH().length);
  }

  @Test
  public void publicKeyHasFixedLength() {
    for (int i = 0; i < 4; i++) {
      AsymmetricCipherKeyPair kp = freshKeyPair();
      byte[] pkBytes = ((FalconPublicKeyParameters) kp.getPublic()).getH();
      assertEquals(FNDSA.PUBLIC_KEY_LENGTH, pkBytes.length);
    }
  }

  @Test
  public void privateKeyEncodingHasFixedLength() {
    for (int i = 0; i < 4; i++) {
      AsymmetricCipherKeyPair kp = freshKeyPair();
      byte[] skBytes = ((FalconPrivateKeyParameters) kp.getPrivate()).getEncoded();
      assertEquals(FNDSA.PRIVATE_KEY_LENGTH, skBytes.length);
    }
  }

  @Test
  public void signProducesVerifiableSignatureWithinBound() {
    byte[] msg = "hello, fn-dsa".getBytes();
    byte[] sig = FNDSA.sign(sk.getEncoded(), msg);
    assertTrue("signature must be non-empty", sig.length > 0);
    assertTrue(
        "signature must respect protocol-level upper bound",
        sig.length <= FNDSA.SIGNATURE_LENGTH);
    assertTrue(FNDSA.verify(pk.getH(), msg, sig));
  }

  @Test
  public void signatureBoundaryAtMaxAcceptedByLengthCheck() {
    byte[] sig = new byte[FNDSA.SIGNATURE_LENGTH];
    keypair.validateSignature(sig);
  }

  @Test
  public void signatureBoundaryAboveMaxRejected() {
    byte[] sig = new byte[FNDSA.SIGNATURE_LENGTH + 1];
    try {
      keypair.validateSignature(sig);
      fail("signature longer than upper bound should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void minimalValidLengthAcceptedByLengthCheck() {
    byte[] sig = new byte[1];
    keypair.validateSignature(sig);
  }

  @Test
  public void emptySignatureRejectedByLengthCheck() {
    byte[] sig = new byte[0];
    try {
      keypair.validateSignature(sig);
      fail("empty signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void verifyRejectsSignatureLongerThanUpperBound() {
    byte[] msg = new byte[] {1, 2, 3};
    byte[] tooLong = new byte[FNDSA.SIGNATURE_LENGTH + 1];
    try {
      FNDSA.verify(pk.getH(), msg, tooLong);
      fail("signature exceeding upper bound should be rejected at static verify");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void verifyRejectsEmptySignature() {
    byte[] msg = new byte[] {1, 2, 3};
    byte[] empty = new byte[0];
    try {
      FNDSA.verify(pk.getH(), msg, empty);
      fail("empty signature should be rejected at static verify");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[FNDSA.PUBLIC_KEY_LENGTH - 1];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[16];
    try {
      FNDSA.verify(badPk, msg, sig);
      fail("short public key should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[16];
    try {
      FNDSA.verify(pk.getH(), null, sig);
      fail("null message should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
    }
  }

  @Test
  public void signatureBoundToMessage() {
    byte[] msg = "hello".getBytes();
    byte[] sig = rawSign(msg);
    byte[] tamperedMsg = "hellp".getBytes();
    assertFalse(keypair.verify(tamperedMsg, sig));
  }

  @Test
  public void tamperedSignatureFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    sig[0] ^= 0x01;
    assertFalse(keypair.verify(msg, sig));
  }

  @Test
  public void wrongPublicKeyFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    AsymmetricCipherKeyPair other = freshKeyPair();
    byte[] otherPk = ((FalconPublicKeyParameters) other.getPublic()).getH();
    assertFalse(FNDSA.verify(otherPk, msg, sig));
  }

  @Test
  public void crossAlgoSignatureRejected() {
    // FN-DSA upper bound is 752 bytes; ML-DSA-44 (2420), ML-DSA-65 (3309),
    // SLH-DSA (7856) all exceed it and must be rejected at the length check.
    byte[] msg = "cross-algo".getBytes();
    int[] foreignLengths = {2420, 3309, 7856};
    for (int len : foreignLengths) {
      byte[] foreign = new byte[len];
      try {
        FNDSA.verify(pk.getH(), msg, foreign);
        fail("foreign-scheme signature length " + len + " should be rejected for FN-DSA");
      } catch (IllegalArgumentException expected) {
        assertTrue(expected.getMessage().contains("signature length"));
      }
    }
  }

  @Test
  public void emptyMessageVerifiesConsistently() {
    byte[] msg = new byte[0];
    byte[] sig = rawSign(msg);
    assertTrue(keypair.verify(msg, sig));
  }

  @Test
  public void keypairBoundInstanceSignsAndVerifies() {
    FNDSA signer = new FNDSA();
    byte[] msg = "keypair-bound".getBytes();
    byte[] sig = signer.sign(msg);
    assertTrue(sig.length > 0 && sig.length <= FNDSA.SIGNATURE_LENGTH);
    assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void fromSeedIsDeterministic() {
    byte[] seed = new byte[FNDSA.SEED_LENGTH];
    for (int i = 0; i < seed.length; i++) {
      seed[i] = (byte) i;
    }
    FNDSA a = new FNDSA(seed);
    FNDSA b = new FNDSA(seed);
    assertArrayEquals(a.getPublicKey(), b.getPublicKey());
    assertArrayEquals(a.getPrivateKey(), b.getPrivateKey());
  }

  @Test(expected = IllegalArgumentException.class)
  public void invalidSeedLengthRejected() {
    new FNDSA(new byte[FNDSA.SEED_LENGTH - 1]);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void derivePublicKeyFromEncodedPrivateKeyUnsupported() {
    FNDSA.derivePublicKey(sk.getEncoded());
  }

  @Test
  public void computeAddressIs21Bytes() {
    assertEquals(21, FNDSA.computeAddress(pk.getH()).length);
  }

  @Test
  public void registryDispatchMatchesDirectCalls() {
    byte[] msg = "registry-dispatch".getBytes();
    byte[] sigDirect = FNDSA.sign(sk.getEncoded(), msg);
    assertTrue(PQSchemeRegistry.verify(
        PQScheme.FN_DSA_512, pk.getH(), msg, sigDirect));
    byte[] sigViaRegistry = PQSchemeRegistry.sign(
        PQScheme.FN_DSA_512, sk.getEncoded(), msg);
    assertTrue(FNDSA.verify(pk.getH(), msg, sigViaRegistry));
    assertEquals(FNDSA.PUBLIC_KEY_LENGTH,
        PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512));
    assertEquals(FNDSA.SIGNATURE_LENGTH,
        PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512));
  }

  @Test
  public void registryIsValidSignatureLengthRespectsUpperBound() {
    assertTrue(PQSchemeRegistry.isValidSignatureLength(PQScheme.FN_DSA_512, 1));
    assertTrue(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.FN_DSA_512, FNDSA.SIGNATURE_LENGTH));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(PQScheme.FN_DSA_512, 0));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.FN_DSA_512, FNDSA.SIGNATURE_LENGTH + 1));
  }

  @Test
  public void registryComputeAddressMatchesDirect() {
    assertArrayEquals(
        FNDSA.computeAddress(pk.getH()),
        PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pk.getH()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void seedConstructorRejectsNull() {
    new FNDSA((byte[]) null);
  }

  @Test
  public void keypairConstructorRejectsNullPrivateKey() {
    try {
      new FNDSA(null, pk.getH());
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsWrongPrivateKeyLength() {
    try {
      new FNDSA(new byte[FNDSA.PRIVATE_KEY_LENGTH - 1], pk.getH());
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsNullPublicKey() {
    try {
      new FNDSA(sk.getEncoded(), null);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsWrongPublicKeyLength() {
    try {
      new FNDSA(sk.getEncoded(), new byte[FNDSA.PUBLIC_KEY_LENGTH + 1]);
      fail("over-long public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void extendedPrivateKeyRoundTripsThroughFromAndGetters() {
    byte[] extended = keypair.getPrivateKeyWithPublicKey();
    assertEquals(FNDSA.PRIVATE_KEY_WITH_PUBLIC_KEY_LENGTH, extended.length);
    FNDSA restored = FNDSA.fromPrivateKeyWithPublicKey(extended);
    assertArrayEquals(keypair.getPrivateKey(), restored.getPrivateKey());
    assertArrayEquals(keypair.getPublicKey(), restored.getPublicKey());
    // The recovered keypair must produce verifiable signatures and recover its address.
    byte[] msg = "extended-key-roundtrip".getBytes();
    byte[] sig = restored.sign(msg);
    assertTrue(restored.verify(msg, sig));
    assertArrayEquals(keypair.getAddress(), restored.getAddress());
  }

  @Test(expected = IllegalArgumentException.class)
  public void fromExtendedPrivateKeyRejectsNull() {
    FNDSA.fromPrivateKeyWithPublicKey(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void fromExtendedPrivateKeyRejectsWrongLength() {
    FNDSA.fromPrivateKeyWithPublicKey(new byte[FNDSA.PRIVATE_KEY_LENGTH]);
  }

  @Test
  public void derivePublicKeyFromExtendedFormReturnsAppendedPublicKey() {
    byte[] extended = keypair.getPrivateKeyWithPublicKey();
    byte[] derived = FNDSA.derivePublicKey(extended);
    assertArrayEquals(keypair.getPublicKey(), derived);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void derivePublicKeyRejectsNull() {
    FNDSA.derivePublicKey(null);
  }

  @Test
  public void staticSignAcceptsExtendedPrivateKey() {
    byte[] extended = keypair.getPrivateKeyWithPublicKey();
    byte[] msg = "static-sign-extended".getBytes();
    byte[] sig = FNDSA.sign(extended, msg);
    assertTrue(sig.length > 0 && sig.length <= FNDSA.SIGNATURE_LENGTH);
    assertTrue(FNDSA.verify(pk.getH(), msg, sig));
  }

  @Test
  public void staticSignRejectsNullPrivateKey() {
    try {
      FNDSA.sign(null, new byte[] {1});
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void staticSignRejectsWrongPrivateKeyLength() {
    try {
      FNDSA.sign(new byte[FNDSA.PRIVATE_KEY_LENGTH - 1], new byte[] {1});
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void staticSignRejectsNullMessage() {
    try {
      FNDSA.sign(sk.getEncoded(), null);
      fail("null message must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
    }
  }

  @Test
  public void staticVerifyRejectsNullPublicKey() {
    try {
      FNDSA.verify(null, new byte[] {1}, new byte[16]);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void unknownPqSchemeResolvesToFnDsa512() {
    assertEquals(PQScheme.FN_DSA_512,
        PQSchemeRegistry.resolve(PQScheme.UNKNOWN_PQ_SCHEME));
    assertTrue(PQSchemeRegistry.contains(PQScheme.UNKNOWN_PQ_SCHEME));
    assertEquals(FNDSA.PUBLIC_KEY_LENGTH,
        PQSchemeRegistry.getPublicKeyLength(PQScheme.UNKNOWN_PQ_SCHEME));
    assertEquals(FNDSA.SIGNATURE_LENGTH,
        PQSchemeRegistry.getSignatureLength(PQScheme.UNKNOWN_PQ_SCHEME));
    assertTrue(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.UNKNOWN_PQ_SCHEME, FNDSA.SIGNATURE_LENGTH));
    assertArrayEquals(
        FNDSA.computeAddress(pk.getH()),
        PQSchemeRegistry.computeAddress(PQScheme.UNKNOWN_PQ_SCHEME, pk.getH()));

    byte[] msg = "unknown-resolves-to-falcon".getBytes();
    byte[] sig = PQSchemeRegistry.sign(
        PQScheme.UNKNOWN_PQ_SCHEME, sk.getEncoded(), msg);
    assertTrue(PQSchemeRegistry.verify(
        PQScheme.UNKNOWN_PQ_SCHEME, pk.getH(), msg, sig));
    assertTrue(FNDSA.verify(pk.getH(), msg, sig));
  }
}
