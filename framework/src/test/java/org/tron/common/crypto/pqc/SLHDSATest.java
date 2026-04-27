package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.junit.Before;
import org.junit.Test;
import org.tron.protos.Protocol.SignatureScheme;

public class SLHDSATest {

  private static final SLHDSAParameters PARAMS = SLHDSAParameters.sha2_128s;

  private SLHDSA keypair;
  private SLHDSAPublicKeyParameters pk;
  private SLHDSAPrivateKeyParameters sk;

  @Before
  public void setUp() {
    SLHDSAKeyPairGenerator gen = new SLHDSAKeyPairGenerator();
    gen.init(new SLHDSAKeyGenerationParameters(new SecureRandom(), PARAMS));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    pk = (SLHDSAPublicKeyParameters) kp.getPublic();
    sk = (SLHDSAPrivateKeyParameters) kp.getPrivate();
    keypair = new SLHDSA(sk.getEncoded(), pk.getEncoded());
  }

  private static byte[] freshPrivateKey() {
    SLHDSAKeyPairGenerator gen = new SLHDSAKeyPairGenerator();
    gen.init(new SLHDSAKeyGenerationParameters(new SecureRandom(), PARAMS));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    return ((SLHDSAPrivateKeyParameters) kp.getPrivate()).getEncoded();
  }

  private byte[] rawSign(byte[] message) {
    SLHDSASigner signer = new SLHDSASigner();
    signer.init(true, sk);
    try {
      return signer.generateSignature(message);
    } catch (Exception e) {
      throw new AssertionError("failed to sign in test setup", e);
    }
  }

  @Test
  public void schemeAndLengthsMatchFips205() {
    assertEquals(SignatureScheme.SLH_DSA, keypair.getScheme());
    assertEquals(SLHDSA.PUBLIC_KEY_LENGTH, keypair.getPublicKeyLength());
    assertEquals(SLHDSA.SIGNATURE_LENGTH, keypair.getSignatureLength());
    assertEquals(SLHDSA.PUBLIC_KEY_LENGTH, pk.getEncoded().length);
  }

  @Test
  public void privateKeyLengthMatchesFips205() {
    byte[] skBytes = freshPrivateKey();
    assertEquals(SLHDSA.PRIVATE_KEY_LENGTH, skBytes.length);
  }

  @Test
  public void derivedPublicKeyLengthMatchesFips205() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = SLHDSA.derivePublicKey(skBytes);
    assertEquals(SLHDSA.PUBLIC_KEY_LENGTH, pkBytes.length);
  }

  @Test
  public void signProducesVerifiableSignature() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = SLHDSA.derivePublicKey(skBytes);
    byte[] message = "hello, slh-dsa".getBytes();

    byte[] sig = SLHDSA.sign(skBytes, message);
    assertEquals(SLHDSA.SIGNATURE_LENGTH, sig.length);

    assertTrue(SLHDSA.verify(pkBytes, message, sig));
  }

  @Test
  public void roundTripSignVerifyWithTamperRejected() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = SLHDSA.derivePublicKey(skBytes);
    byte[] message = "roundtrip".getBytes();
    byte[] sig = SLHDSA.sign(skBytes, message);

    assertTrue(SLHDSA.verify(pkBytes, message, sig));

    byte[] tampered = sig.clone();
    tampered[0] ^= 0x01;
    if (SLHDSA.verify(pkBytes, message, tampered)) {
      fail("tampered signature should not verify");
    }
  }

  @Test
  public void deterministicPublicKeyDerivation() {
    byte[] skBytes = freshPrivateKey();
    byte[] pk1 = SLHDSA.derivePublicKey(skBytes);
    byte[] pk2 = SLHDSA.derivePublicKey(skBytes);
    assertArrayEquals(pk1, pk2);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsShortPrivateKey() {
    SLHDSA.sign(new byte[10], new byte[4]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsNullMessage() {
    byte[] skBytes = freshPrivateKey();
    SLHDSA.sign(skBytes, null);
  }

  @Test
  public void validSignatureVerifiesViaInstance() {
    byte[] msg = "tron-pq-slhdsa".getBytes();
    byte[] sig = rawSign(msg);
    assertEquals(SLHDSA.SIGNATURE_LENGTH, sig.length);
    assertTrue(keypair.verify(msg, sig));
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
    SLHDSAKeyPairGenerator gen = new SLHDSAKeyPairGenerator();
    gen.init(new SLHDSAKeyGenerationParameters(new SecureRandom(), PARAMS));
    SLHDSAPublicKeyParameters otherPk =
        (SLHDSAPublicKeyParameters) gen.generateKeyPair().getPublic();
    assertFalse(SLHDSA.verify(otherPk.getEncoded(), msg, sig));
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[SLHDSA.PUBLIC_KEY_LENGTH - 1];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[SLHDSA.SIGNATURE_LENGTH];
    try {
      SLHDSA.verify(badPk, msg, sig);
      fail("short public key should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void invalidSignatureLengthRejected() {
    byte[] badSig = new byte[SLHDSA.SIGNATURE_LENGTH - 1];
    byte[] msg = new byte[] {1};
    try {
      SLHDSA.verify(pk.getEncoded(), msg, badSig);
      fail("short signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[SLHDSA.SIGNATURE_LENGTH];
    try {
      SLHDSA.verify(pk.getEncoded(), null, sig);
      fail("null message should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
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
    SLHDSA signer = new SLHDSA();
    byte[] msg = "keypair-bound".getBytes();
    byte[] sig = signer.sign(msg);
    assertEquals(SLHDSA.SIGNATURE_LENGTH, sig.length);
    assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void fromSeedIsDeterministic() {
    byte[] seed = new byte[SLHDSA.SEED_LENGTH];
    for (int i = 0; i < seed.length; i++) {
      seed[i] = (byte) i;
    }
    SLHDSA a = new SLHDSA(seed);
    SLHDSA b = new SLHDSA(seed);
    assertArrayEquals(a.getPublicKey(), b.getPublicKey());
    assertArrayEquals(a.getPrivateKey(), b.getPrivateKey());
  }

  @Test(expected = IllegalArgumentException.class)
  public void invalidSeedLengthRejected() {
    new SLHDSA(new byte[SLHDSA.SEED_LENGTH - 1]);
  }

  @Test
  public void computeAddressIs21Bytes() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = SLHDSA.derivePublicKey(skBytes);
    assertEquals(21, SLHDSA.computeAddress(pkBytes).length);
  }

  @Test
  public void crossAlgoSignatureRejected() {
    // SLH-DSA signature size differs from ML-DSA-44 (2420) and ML-DSA-65 (3309).
    // A signature of the wrong length must be rejected at the length check.
    byte[] msg = "cross-algo".getBytes();
    byte[] mlDsa44Size = new byte[2420];
    try {
      SLHDSA.verify(pk.getEncoded(), msg, mlDsa44Size);
      fail("ML-DSA-44-sized signature should be rejected for SLH-DSA");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void registryDispatchMatchesDirectCalls() {
    byte[] msg = "registry-dispatch".getBytes();
    byte[] sigDirect = SLHDSA.sign(sk.getEncoded(), msg);
    assertTrue(PqSignatureRegistry.verify(
        SignatureScheme.SLH_DSA, pk.getEncoded(), msg, sigDirect));
    byte[] sigViaRegistry = PqSignatureRegistry.sign(
        SignatureScheme.SLH_DSA, sk.getEncoded(), msg);
    assertTrue(SLHDSA.verify(pk.getEncoded(), msg, sigViaRegistry));
    assertEquals(SLHDSA.PUBLIC_KEY_LENGTH,
        PqSignatureRegistry.getPublicKeyLength(SignatureScheme.SLH_DSA));
    assertEquals(SLHDSA.SIGNATURE_LENGTH,
        PqSignatureRegistry.getSignatureLength(SignatureScheme.SLH_DSA));
  }
}
