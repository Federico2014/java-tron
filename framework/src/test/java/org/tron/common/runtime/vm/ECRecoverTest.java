package org.tron.common.runtime.vm;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.core.vm.PrecompiledContracts.ECRecover;

/**
 * Direct execution regression baseline for the ECRECOVER precompile (address 0x01).
 *
 * <p>Before this class the precompile body had no asserting test — it was only
 * invoked once without checking the recovered address, plus a non-asserting
 * microbenchmark. These tests exercise the success path (recovered address must
 * match the signer) and the failure paths (bad v, malformed r/s, short input),
 * all of which must return an empty result rather than throw.
 *
 * <p>ECDSA signing here is deterministic (RFC 6979), so a fixed private key
 * yields a stable signature and the test needs no externally pinned r/s vector.
 */
public class ECRecoverTest {

  private static final ECRecover EC_RECOVER = new ECRecover();

  // Fixed placeholder private key — deterministic so the recovered address is stable.
  private static final BigInteger PRIV =
      new BigInteger("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4", 16);
  private static final byte[] HASH =
      Hex.decode("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad");

  private static byte[] fixed32(BigInteger b) {
    byte[] x = b.toByteArray();
    byte[] out = new byte[32];
    if (x.length > 32) {
      System.arraycopy(x, x.length - 32, out, 0, 32);
    } else {
      System.arraycopy(x, 0, out, 32 - x.length, x.length);
    }
    return out;
  }

  /** Build a 128-byte ECRECOVER input: hash(32) | v(32, right-aligned) | r(32) | s(32). */
  private static byte[] buildInput(byte[] hash, ECDSASignature sig, byte v) {
    byte[] input = new byte[128];
    System.arraycopy(hash, 0, input, 0, 32);
    input[63] = v;
    System.arraycopy(fixed32(sig.r), 0, input, 64, 32);
    System.arraycopy(fixed32(sig.s), 0, input, 96, 32);
    return input;
  }

  @Test
  public void recoversSignerAddress() {
    ECKey key = ECKey.fromPrivate(PRIV);
    ECDSASignature sig = key.sign(HASH);

    Pair<Boolean, byte[]> result = EC_RECOVER.execute(buildInput(HASH, sig, sig.v));

    assertTrue(result.getLeft());
    assertEquals("recovered output must be a 32-byte word", 32, result.getRight().length);

    // The precompile left-pads the 21-byte TRON address into a 32-byte word.
    byte[] expected = key.getAddress();
    byte[] tail = Arrays.copyOfRange(result.getRight(), 32 - expected.length, 32);
    assertArrayEquals("recovered address must match the signer", expected, tail);
  }

  @Test
  public void rejectsInvalidRecoveryId() {
    ECKey key = ECKey.fromPrivate(PRIV);
    ECDSASignature sig = key.sign(HASH);

    // v = 17 is not a valid recovery id; recovery must fail -> empty result.
    Pair<Boolean, byte[]> result = EC_RECOVER.execute(buildInput(HASH, sig, (byte) 17));

    assertTrue(result.getLeft());
    assertEquals("invalid v must yield empty output", 0, result.getRight().length);
  }

  @Test
  public void rejectsNonZeroVPadding() {
    ECKey key = ECKey.fromPrivate(PRIV);
    ECDSASignature sig = key.sign(HASH);

    // The 32-byte v word must be zero except its last byte; pollute a high byte.
    byte[] input = buildInput(HASH, sig, sig.v);
    input[32] = 0x01;

    Pair<Boolean, byte[]> result = EC_RECOVER.execute(input);
    assertEquals("non-zero v padding must yield empty output", 0, result.getRight().length);
  }

  @Test
  public void rejectsZeroSignatureComponents() {
    // r = s = 0 is not a valid signature; must fail gracefully.
    byte[] input = new byte[128];
    System.arraycopy(HASH, 0, input, 0, 32);
    input[63] = 27;

    Pair<Boolean, byte[]> result = EC_RECOVER.execute(input);
    assertTrue(result.getLeft());
    assertEquals("zero r/s must yield empty output", 0, result.getRight().length);
  }

  @Test
  public void handlesShortInputWithoutThrowing() {
    // Truncated input must not throw — the precompile swallows the exception
    // and returns an empty result.
    Pair<Boolean, byte[]> result = EC_RECOVER.execute(new byte[64]);
    assertTrue(result.getLeft());
    assertEquals(0, result.getRight().length);
  }
}
