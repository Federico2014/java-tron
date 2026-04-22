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

public class MLDSA44VerifierTest {

  private MLDSA44Verifier verifier;
  private MLDSAPublicKeyParameters pk;
  private MLDSAPrivateKeyParameters sk;

  @Before
  public void setUp() {
    verifier = new MLDSA44Verifier();
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
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
    assertEquals(SignatureScheme.ML_DSA_44, verifier.getScheme());
    assertEquals(1312, verifier.getPublicKeyLength());
    assertEquals(2420, verifier.getSignatureLength());
    assertArrayEquals(pk.getEncoded(), pk.getEncoded());
    assertEquals(1312, pk.getEncoded().length);
  }

  @Test
  public void validSignatureVerifies() {
    byte[] msg = "tron-pq-mldsa44".getBytes();
    byte[] sig = sign(msg);
    assertEquals(2420, sig.length);
    assertTrue(verifier.verify(pk.getEncoded(), msg, sig));
  }

  @Test
  public void signatureBoundToMessage() {
    byte[] msg = "hello".getBytes();
    byte[] sig = sign(msg);
    byte[] tamperedMsg = "hellp".getBytes();
    assertFalse(verifier.verify(pk.getEncoded(), tamperedMsg, sig));
  }

  @Test
  public void tamperedSignatureFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = sign(msg);
    sig[0] ^= 0x01;
    assertFalse(verifier.verify(pk.getEncoded(), msg, sig));
  }

  @Test
  public void wrongPublicKeyFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = sign(msg);
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
    MLDSAPublicKeyParameters otherPk =
        (MLDSAPublicKeyParameters) gen.generateKeyPair().getPublic();
    assertFalse(verifier.verify(otherPk.getEncoded(), msg, sig));
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[1311];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[2420];
    try {
      verifier.verify(badPk, msg, sig);
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
      verifier.verify(pk.getEncoded(), msg, badSig);
      fail("short signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[2420];
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
}
