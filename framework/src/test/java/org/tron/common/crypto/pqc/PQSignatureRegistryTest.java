package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.tron.protos.Protocol.SignatureScheme;

public class PQSignatureRegistryTest {

  @Test
  public void mlDsa44Registered() {
    assertTrue(PQSignatureRegistry.contains(SignatureScheme.ML_DSA_44));
    assertEquals(MLDSA44.PUBLIC_KEY_LENGTH,
        PQSignatureRegistry.getPublicKeyLength(SignatureScheme.ML_DSA_44));
    assertEquals(MLDSA44.SIGNATURE_LENGTH,
        PQSignatureRegistry.getSignatureLength(SignatureScheme.ML_DSA_44));
  }

  @Test
  public void mlDsa65Registered() {
    assertTrue(PQSignatureRegistry.contains(SignatureScheme.ML_DSA_65));
    assertEquals(MLDSA65.PUBLIC_KEY_LENGTH,
        PQSignatureRegistry.getPublicKeyLength(SignatureScheme.ML_DSA_65));
    assertEquals(MLDSA65.SIGNATURE_LENGTH,
        PQSignatureRegistry.getSignatureLength(SignatureScheme.ML_DSA_65));
  }

  @Test
  public void mlDsa44VerifyRoundTrip() {
    MLDSA44 keypair = new MLDSA44();
    byte[] msg = "registry-44".getBytes();
    byte[] sig = keypair.sign(msg);
    assertTrue(PQSignatureRegistry.verify(
        SignatureScheme.ML_DSA_44, keypair.getPublicKey(), msg, sig));
  }

  @Test
  public void mlDsa65VerifyRoundTrip() {
    MLDSA65 keypair = new MLDSA65();
    byte[] msg = "registry-65".getBytes();
    byte[] sig = keypair.sign(msg);
    assertTrue(PQSignatureRegistry.verify(
        SignatureScheme.ML_DSA_65, keypair.getPublicKey(), msg, sig));
  }

  @Test
  public void ecdsaNotRegistered() {
    assertFalse(PQSignatureRegistry.contains(SignatureScheme.ECDSA_SECP256K1));
    try {
      PQSignatureRegistry.getPublicKeyLength(SignatureScheme.ECDSA_SECP256K1);
      fail("expected IllegalArgumentException for ECDSA_SECP256K1");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("ECDSA_SECP256K1"));
    }
  }

  @Test
  public void sm2NotRegistered() {
    assertFalse(PQSignatureRegistry.contains(SignatureScheme.SM2_SM3));
    try {
      PQSignatureRegistry.verify(
          SignatureScheme.SM2_SM3, new byte[0], new byte[0], new byte[0]);
      fail("expected IllegalArgumentException for SM2_SM3");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("SM2_SM3"));
    }
  }

  @Test
  public void unknownSchemeRejected() {
    assertFalse(PQSignatureRegistry.contains(SignatureScheme.UNKNOWN_SIG_SCHEME));
    try {
      PQSignatureRegistry.getSignatureLength(SignatureScheme.UNKNOWN_SIG_SCHEME);
      fail("expected IllegalArgumentException for UNKNOWN_SIG_SCHEME");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("UNKNOWN_SIG_SCHEME"));
    }
  }
}
