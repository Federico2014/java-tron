package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

/**
 * Covers the static dispatch helpers of {@link PQSchemeRegistry} and the
 * defensive paths exercised by callers passing {@code null}, {@code UNRECOGNIZED}
 * or wrong-shaped public keys.
 */
public class PQSchemeRegistryTest {

  @Test
  public void containsRejectsNullScheme() {
    assertFalse(PQSchemeRegistry.contains(null));
  }

  @Test
  public void containsRejectsUnrecognized() {
    assertFalse(PQSchemeRegistry.contains(PQScheme.UNRECOGNIZED));
  }

  @Test
  public void containsAcceptsRegisteredScheme() {
    assertTrue(PQSchemeRegistry.contains(PQScheme.FN_DSA_512));
  }

  @Test
  public void getSeedLengthReturnsRegisteredValue() {
    assertEquals(FNDSA.SEED_LENGTH,
        PQSchemeRegistry.getSeedLength(PQScheme.FN_DSA_512));
    // UNKNOWN_PQ_SCHEME normalizes to FN_DSA_512.
    assertEquals(FNDSA.SEED_LENGTH,
        PQSchemeRegistry.getSeedLength(PQScheme.UNKNOWN_PQ_SCHEME));
  }

  @Test
  public void getPrivateKeyLengthReturnsRegisteredValue() {
    assertEquals(FNDSA.PRIVATE_KEY_LENGTH,
        PQSchemeRegistry.getPrivateKeyLength(PQScheme.FN_DSA_512));
  }

  @Test
  public void fromSeedDispatchesToFalcon() {
    byte[] seed = new byte[FNDSA.SEED_LENGTH];
    Arrays.fill(seed, (byte) 0x07);
    PQSignature sig = PQSchemeRegistry.fromSeed(PQScheme.FN_DSA_512, seed);
    assertNotNull(sig);
    assertEquals(PQScheme.FN_DSA_512, sig.getScheme());
    // Same seed must yield deterministic keypair across direct and dispatched paths.
    FNDSA direct = new FNDSA(seed);
    assertArrayEquals(direct.getPublicKey(), sig.getPublicKey());
    assertArrayEquals(direct.getPrivateKey(), sig.getPrivateKey());
  }

  @Test
  public void fromKeypairDispatchesAndPreservesAddress() {
    byte[] seed = new byte[FNDSA.SEED_LENGTH];
    Arrays.fill(seed, (byte) 0x09);
    FNDSA src = new FNDSA(seed);
    PQSignature sig = PQSchemeRegistry.fromKeypair(
        PQScheme.FN_DSA_512, src.getPrivateKey(), src.getPublicKey());
    assertArrayEquals(src.getAddress(), sig.getAddress());
    byte[] msg = "from-keypair".getBytes();
    byte[] s = sig.sign(msg);
    assertTrue(sig.verify(msg, s));
  }

  @Test
  public void deriveHashRejectsNullPublicKey() {
    try {
      PQSchemeRegistry.deriveHash(PQScheme.FN_DSA_512, null);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void deriveHashRejectsWrongLengthPublicKey() {
    try {
      PQSchemeRegistry.deriveHash(
          PQScheme.FN_DSA_512, new byte[FNDSA.PUBLIC_KEY_LENGTH - 1]);
      fail("short public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void requireRejectsNullScheme() {
    try {
      PQSchemeRegistry.getPublicKeyLength(null);
      fail("null scheme must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("scheme"));
    }
  }

  @Test
  public void requireRejectsUnrecognizedScheme() {
    try {
      PQSchemeRegistry.getPublicKeyLength(PQScheme.UNRECOGNIZED);
      fail("UNRECOGNIZED scheme must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("PQSignature registered"));
    }
  }

  @Test
  public void resolvePassesThroughNonDefaultSchemes() {
    assertEquals(PQScheme.FN_DSA_512,
        PQSchemeRegistry.resolve(PQScheme.FN_DSA_512));
    // null should pass through so contains/require can decide.
    assertTrue(PQSchemeRegistry.resolve(null) == null);
  }

  @Test
  public void isValidSignatureLengthRejectsZero() {
    assertFalse(PQSchemeRegistry.isValidSignatureLength(PQScheme.FN_DSA_512, 0));
  }
}
