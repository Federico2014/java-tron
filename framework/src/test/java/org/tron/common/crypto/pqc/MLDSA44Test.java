package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.junit.Before;
import org.junit.Test;
import org.tron.protos.Protocol.SignatureScheme;

public class MLDSA44Test {

  private MLDSA44 keypair;
  private MLDSAPublicKeyParameters pk;
  private MLDSAPrivateKeyParameters sk;

  @Before
  public void setUp() {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    pk = (MLDSAPublicKeyParameters) kp.getPublic();
    sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    keypair = new MLDSA44(sk.getEncoded(), pk.getEncoded());
  }

  private static byte[] freshPrivateKey() {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    return ((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded();
  }

  private byte[] rawSign(byte[] message) {
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, sk);
    signer.update(message, 0, message.length);
    try {
      return signer.generateSignature();
    } catch (Exception e) {
      throw new AssertionError("failed to sign in test setup", e);
    }
  }

  @Test
  public void schemeAndLengthsMatchFips204() {
    assertEquals(SignatureScheme.ML_DSA_44, keypair.getScheme());
    assertEquals(1312, keypair.getPublicKeyLength());
    assertEquals(2420, keypair.getSignatureLength());
    assertEquals(1312, pk.getEncoded().length);
  }

  @Test
  public void privateKeyLengthMatchesFips204() {
    byte[] skBytes = freshPrivateKey();
    assertEquals(MLDSA44.PRIVATE_KEY_LENGTH, skBytes.length);
  }

  @Test
  public void derivedPublicKeyLengthMatchesFips204() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = MLDSA44.derivePublicKey(skBytes);
    assertEquals(MLDSA44.PUBLIC_KEY_LENGTH, pkBytes.length);
  }

  @Test
  public void signProducesVerifiableSignature() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = MLDSA44.derivePublicKey(skBytes);
    byte[] message = "hello, ml-dsa-44".getBytes();

    byte[] sig = MLDSA44.sign(skBytes, message);
    assertEquals(MLDSA44.SIGNATURE_LENGTH, sig.length);

    assertTrue(MLDSA44.verify(pkBytes, message, sig));
  }

  @Test
  public void roundTripSignVerifyWithTamperRejected() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = MLDSA44.derivePublicKey(skBytes);
    byte[] message = "roundtrip".getBytes();
    byte[] sig = MLDSA44.sign(skBytes, message);

    assertTrue(MLDSA44.verify(pkBytes, message, sig));

    byte[] tampered = sig.clone();
    tampered[0] ^= 0x01;
    if (MLDSA44.verify(pkBytes, message, tampered)) {
      fail("tampered signature should not verify");
    }
  }

  @Test
  public void deterministicPublicKeyDerivation() {
    byte[] skBytes = freshPrivateKey();
    byte[] pk1 = MLDSA44.derivePublicKey(skBytes);
    byte[] pk2 = MLDSA44.derivePublicKey(skBytes);
    assertArrayEquals(pk1, pk2);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsShortPrivateKey() {
    MLDSA44.sign(new byte[10], new byte[4]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsNullMessage() {
    byte[] skBytes = freshPrivateKey();
    MLDSA44.sign(skBytes, null);
  }

  @Test
  public void validSignatureVerifiesViaInstance() {
    byte[] msg = "tron-pq-mldsa44".getBytes();
    byte[] sig = rawSign(msg);
    assertEquals(2420, sig.length);
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
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
    MLDSAPublicKeyParameters otherPk =
        (MLDSAPublicKeyParameters) gen.generateKeyPair().getPublic();
    assertFalse(MLDSA44.verify(otherPk.getEncoded(), msg, sig));
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[1311];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[2420];
    try {
      MLDSA44.verify(badPk, msg, sig);
      fail("short public key should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void invalidSignatureLengthRejected() {
    byte[] badSig = new byte[2419];
    byte[] msg = new byte[] {1};
    try {
      MLDSA44.verify(pk.getEncoded(), msg, badSig);
      fail("short signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[2420];
    try {
      MLDSA44.verify(pk.getEncoded(), null, sig);
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
    MLDSA44 signer = new MLDSA44();
    byte[] msg = "keypair-bound".getBytes();
    byte[] sig = signer.sign(msg);
    assertEquals(MLDSA44.SIGNATURE_LENGTH, sig.length);
    assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void fromSeedIsDeterministic() {
    byte[] seed = new byte[32];
    for (int i = 0; i < seed.length; i++) {
      seed[i] = (byte) i;
    }
    MLDSA44 a = new MLDSA44(seed);
    MLDSA44 b = new MLDSA44(seed);
    assertArrayEquals(a.getPublicKey(), b.getPublicKey());
    assertArrayEquals(a.getPrivateKey(), b.getPrivateKey());
  }

  @Test
  public void computeAddressIs21Bytes() {
    byte[] skBytes = freshPrivateKey();
    byte[] pkBytes = MLDSA44.derivePublicKey(skBytes);
    assertEquals(21, MLDSA44.computeAddress(pkBytes).length);
  }
}
