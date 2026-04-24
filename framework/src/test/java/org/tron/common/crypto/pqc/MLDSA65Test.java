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

public class MLDSA65Test {

  private MLDSA65 keypair;
  private MLDSAPublicKeyParameters pk;
  private MLDSAPrivateKeyParameters sk;

  @Before
  public void setUp() {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    pk = (MLDSAPublicKeyParameters) kp.getPublic();
    sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    keypair = new MLDSA65(sk.getEncoded(), pk.getEncoded());
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
    assertEquals(SignatureScheme.ML_DSA_65, keypair.getScheme());
    assertEquals(1952, keypair.getPublicKeyLength());
    assertEquals(3309, keypair.getSignatureLength());
    assertEquals(1952, pk.getEncoded().length);
  }

  @Test
  public void validSignatureVerifies() {
    byte[] msg = "tron-pq-mldsa65".getBytes();
    byte[] sig = rawSign(msg);
    assertEquals(3309, sig.length);
    assertTrue(keypair.verify(msg, sig));
  }

  @Test
  public void signatureBoundToMessage() {
    byte[] msg = "block-header".getBytes();
    byte[] sig = rawSign(msg);
    byte[] tamperedMsg = "block-footer".getBytes();
    assertFalse(keypair.verify(tamperedMsg, sig));
  }

  @Test
  public void tamperedSignatureFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    sig[sig.length - 1] ^= 0x01;
    assertFalse(keypair.verify(msg, sig));
  }

  @Test
  public void wrongPublicKeyFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
    MLDSAPublicKeyParameters otherPk =
        (MLDSAPublicKeyParameters) gen.generateKeyPair().getPublic();
    assertFalse(MLDSA65.verify(otherPk.getEncoded(), msg, sig));
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[1951];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[3309];
    try {
      MLDSA65.verify(badPk, msg, sig);
      fail("short public key should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void invalidSignatureLengthRejected() {
    byte[] badSig = new byte[3310];
    byte[] msg = new byte[] {1};
    try {
      MLDSA65.verify(pk.getEncoded(), msg, badSig);
      fail("wrong-length signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[3309];
    try {
      MLDSA65.verify(pk.getEncoded(), null, sig);
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
  public void crossSchemeKeyFailsVerification() {
    MLDSAKeyPairGenerator gen44 = new MLDSAKeyPairGenerator();
    gen44.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
    MLDSAPublicKeyParameters pk44 =
        (MLDSAPublicKeyParameters) gen44.generateKeyPair().getPublic();
    byte[] pk44Bytes = pk44.getEncoded();
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[3309];
    try {
      MLDSA65.verify(pk44Bytes, msg, sig);
      fail("ML-DSA-44 key for ML-DSA-65 verifier should be rejected on length");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void keypairBoundInstanceSignsAndVerifies() {
    MLDSA65 signer = new MLDSA65();
    byte[] msg = "keypair-bound".getBytes();
    byte[] sig = signer.sign(msg);
    assertEquals(MLDSA65.SIGNATURE_LENGTH, sig.length);
    assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void fromSeedIsDeterministic() {
    byte[] seed = new byte[32];
    for (int i = 0; i < seed.length; i++) {
      seed[i] = (byte) i;
    }
    MLDSA65 a = new MLDSA65(seed);
    MLDSA65 b = new MLDSA65(seed);
    assertArrayEquals(a.getPublicKey(), b.getPublicKey());
    assertArrayEquals(a.getPrivateKey(), b.getPrivateKey());
  }

  @Test
  public void computeAddressIs21Bytes() {
    byte[] skBytes = MLDSA65.generatePrivateKey();
    byte[] pkBytes = MLDSA65.derivePublicKey(skBytes);
    assertEquals(21, MLDSA65.computeAddress(pkBytes).length);
  }
}
