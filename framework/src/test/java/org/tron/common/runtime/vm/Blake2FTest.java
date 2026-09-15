package org.tron.common.runtime.vm;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.tron.core.vm.PrecompiledContracts.Blake2F;

/**
 * Direct execution regression baseline for the BLAKE2 F-compression precompile
 * (EIP-152, address 0x09 on the compatible-EVM path).
 *
 * <p>The precompile was previously only exercised indirectly through a Solidity
 * contract. These tests pin the canonical EIP-152 "vector 4" input/output pair
 * and the input-validation rules: the input must be exactly 213 bytes and the
 * final flag byte must be 0x00 or 0x01.
 *
 * <p>Input layout (213 bytes): rounds(4) | h(64) | m(128) | t(16) | f(1).
 */
public class Blake2FTest {

  private static final Blake2F BLAKE2F = new Blake2F();

  // EIP-152 test vector 4: rounds = 12, f = 1.
  private static final byte[] VECTOR_4_INPUT = Hex.decode(
      "0000000c"
      + "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
      + "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
      + "6162630000000000000000000000000000000000000000000000000000000000"
      + "0000000000000000000000000000000000000000000000000000000000000000"
      + "0000000000000000000000000000000000000000000000000000000000000000"
      + "0000000000000000000000000000000000000000000000000000000000000000"
      + "03000000000000000000000000000000"
      + "01");

  private static final byte[] VECTOR_4_OUTPUT = Hex.decode(
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
      + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

  @Test
  public void matchesEip152Vector4() {
    Pair<Boolean, byte[]> result = BLAKE2F.execute(VECTOR_4_INPUT);

    assertTrue(result.getLeft());
    assertEquals("output must be 64 bytes", 64, result.getRight().length);
    assertArrayEquals("must match EIP-152 vector 4", VECTOR_4_OUTPUT, result.getRight());
  }

  @Test
  public void energyEqualsRounds() {
    // Gas cost equals the round count (0x0000000c = 12) for well-formed input.
    assertEquals(12L, BLAKE2F.getEnergyForData(VECTOR_4_INPUT));
  }

  @Test
  public void zeroRoundsIsAllowed() {
    byte[] input = VECTOR_4_INPUT.clone();
    input[0] = 0;
    input[1] = 0;
    input[2] = 0;
    input[3] = 0;

    Pair<Boolean, byte[]> result = BLAKE2F.execute(input);
    assertTrue(result.getLeft());
    assertEquals(64, result.getRight().length);
    assertEquals(0L, BLAKE2F.getEnergyForData(input));
  }

  @Test
  public void rejectsWrongLength() {
    // 212 bytes — one short of the required 213.
    byte[] input = new byte[212];
    Pair<Boolean, byte[]> result = BLAKE2F.execute(input);
    assertFalse("incorrect length must fail", result.getLeft());
  }

  @Test
  public void rejectsInvalidFinalFlag() {
    byte[] input = VECTOR_4_INPUT.clone();
    input[212] = 0x02; // flag must be 0x00 or 0x01

    Pair<Boolean, byte[]> result = BLAKE2F.execute(input);
    assertFalse("invalid finalization flag must fail", result.getLeft());
    assertEquals("invalid flag must price to zero", 0L, BLAKE2F.getEnergyForData(input));
  }

  @Test
  public void nonFinalBlockFlagZeroAccepted() {
    byte[] input = VECTOR_4_INPUT.clone();
    input[212] = 0x00; // f = 0 is valid (non-final block)

    Pair<Boolean, byte[]> result = BLAKE2F.execute(input);
    assertTrue(result.getLeft());
    assertEquals(64, result.getRight().length);
  }
}
