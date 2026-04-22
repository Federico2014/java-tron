package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.tron.protos.Protocol.SignatureScheme;

public class SignatureVerifierRegistryTest {

  @Test
  public void mlDsa44Registered() {
    SignatureVerifier v = SignatureVerifierRegistry.get(SignatureScheme.ML_DSA_44);
    assertNotNull(v);
    assertSame(SignatureScheme.ML_DSA_44, v.getScheme());
    assertTrue(SignatureVerifierRegistry.contains(SignatureScheme.ML_DSA_44));
  }

  @Test
  public void mlDsa65Registered() {
    SignatureVerifier v = SignatureVerifierRegistry.get(SignatureScheme.ML_DSA_65);
    assertNotNull(v);
    assertSame(SignatureScheme.ML_DSA_65, v.getScheme());
    assertTrue(SignatureVerifierRegistry.contains(SignatureScheme.ML_DSA_65));
  }

  @Test
  public void ecdsaNotRegistered() {
    assertFalse(SignatureVerifierRegistry.contains(SignatureScheme.ECDSA_SECP256K1));
    try {
      SignatureVerifierRegistry.get(SignatureScheme.ECDSA_SECP256K1);
      fail("expected IllegalArgumentException for ECDSA_SECP256K1");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("ECDSA_SECP256K1"));
    }
  }

  @Test
  public void sm2NotRegistered() {
    assertFalse(SignatureVerifierRegistry.contains(SignatureScheme.SM2_SM3));
    try {
      SignatureVerifierRegistry.get(SignatureScheme.SM2_SM3);
      fail("expected IllegalArgumentException for SM2_SM3");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("SM2_SM3"));
    }
  }

  @Test
  public void unknownSchemeRejected() {
    assertFalse(SignatureVerifierRegistry.contains(SignatureScheme.UNKNOWN_SIG_SCHEME));
    try {
      SignatureVerifierRegistry.get(SignatureScheme.UNKNOWN_SIG_SCHEME);
      fail("expected IllegalArgumentException for UNKNOWN_SIG_SCHEME");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("UNKNOWN_SIG_SCHEME"));
    }
  }
}
