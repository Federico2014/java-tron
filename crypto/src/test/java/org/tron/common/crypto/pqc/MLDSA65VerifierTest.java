package org.tron.common.crypto.pqc;

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

public class MLDSA65VerifierTest {

  private MLDSA65Verifier verifier;
  private MLDSAPublicKeyParameters pk;
  private MLDSAPrivateKeyParameters sk;

  @Before
  public void setUp() {
    verifier = new MLDSA65Verifier();
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    pk = (MLDSAPublicKeyParameters) kp.getPublic();
    sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
  }

  private byte[] sign(byte[] message) {
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
    assertEquals(SignatureScheme.ML_DSA_65, verifier.getScheme());
    assertEquals(1952, verifier.getPublicKeyLength());
    assertEquals(3309, verifier.getSignatureLength());
    assertEquals(1952, pk.getEncoded().length);
  }

  @Test
  public void validSignatureVerifies() {
    byte[] msg = "tron-pq-mldsa65".getBytes();
    byte[] sig = sign(msg);
    assertEquals(3309, sig.length);
    assertTrue(verifier.verify(pk.getEncoded(), msg, sig));
  }

  @Test
  public void signatureBoundToMessage() {
    byte[] msg = "block-header".getBytes();
    byte[] sig = sign(msg);
    byte[] tamperedMsg = "block-footer".getBytes();
    assertFalse(verifier.verify(pk.getEncoded(), tamperedMsg, sig));
  }

  @Test
  public void tamperedSignatureFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = sign(msg);
    sig[sig.length - 1] ^= 0x01;
    assertFalse(verifier.verify(pk.getEncoded(), msg, sig));
  }

  @Test
  public void wrongPublicKeyFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = sign(msg);
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
    MLDSAPublicKeyParameters otherPk =
        (MLDSAPublicKeyParameters) gen.generateKeyPair().getPublic();
    assertFalse(verifier.verify(otherPk.getEncoded(), msg, sig));
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[1951];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[3309];
    try {
      verifier.verify(badPk, msg, sig);
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
      verifier.verify(pk.getEncoded(), msg, badSig);
      fail("wrong-length signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[3309];
    try {
      verifier.verify(pk.getEncoded(), null, sig);
      fail("null message should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
    }
  }

  @Test
  public void emptyMessageVerifiesConsistently() {
    byte[] msg = new byte[0];
    byte[] sig = sign(msg);
    assertTrue(verifier.verify(pk.getEncoded(), msg, sig));
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
      verifier.verify(pk44Bytes, msg, sig);
      fail("ML-DSA-44 key for ML-DSA-65 verifier should be rejected on length");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }
}
