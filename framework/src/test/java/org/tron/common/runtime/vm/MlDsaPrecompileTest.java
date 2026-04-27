package org.tron.common.runtime.vm;

import java.util.Arrays;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.MLDSA65;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;

/**
 * Unit tests for the ML-DSA-44 (0x12) and ML-DSA-65 (0x14) verify precompiles.
 * These tests are stateless — no chain DB needed.
 */
public class MlDsaPrecompileTest {

  private static final DataWord MLDSA44_ADDR = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000012");
  private static final DataWord MLDSA65_ADDR = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000014");

  private static final byte[] MESSAGE_HASH = new byte[32];

  static {
    for (int i = 0; i < 32; i++) {
      MESSAGE_HASH[i] = (byte) i;
    }
  }

  @Before
  public void enableProposal() {
    VMConfig.initAllowMlDsa44(1L);
    VMConfig.initAllowMlDsa65(1L);
  }

  @After
  public void disableProposal() {
    VMConfig.initAllowMlDsa44(0L);
    VMConfig.initAllowMlDsa65(0L);
  }

  @Test
  public void switchOff_returnsNull() {
    VMConfig.initAllowMlDsa44(0L);
    VMConfig.initAllowMlDsa65(0L);
    Assert.assertNull(PrecompiledContracts.getContractForAddress(MLDSA44_ADDR));
    Assert.assertNull(PrecompiledContracts.getContractForAddress(MLDSA65_ADDR));
  }

  @Test
  public void switchOn_returnsContracts() {
    Assert.assertNotNull(PrecompiledContracts.getContractForAddress(MLDSA44_ADDR));
    Assert.assertNotNull(PrecompiledContracts.getContractForAddress(MLDSA65_ADDR));
  }

  @Test
  public void mldsa44_validSignature_returnsOne() {
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] input = concat(MESSAGE_HASH, sig, key.getPublicKey());

    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(MLDSA44_ADDR);
    Pair<Boolean, byte[]> result = pc.execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ONE().getData(), result.getRight());
    Assert.assertEquals(4500, pc.getEnergyForData(input));
  }

  @Test
  public void mldsa44_tamperedMessage_returnsZero() {
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] tampered = MESSAGE_HASH.clone();
    tampered[0] ^= 0x01;
    byte[] input = concat(tampered, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA44_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void mldsa44_tamperedSignature_returnsZero() {
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    sig[0] ^= 0x01;
    byte[] input = concat(MESSAGE_HASH, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA44_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void mldsa44_wrongPublicKey_returnsZero() {
    MLDSA44 signer = new MLDSA44();
    MLDSA44 other = new MLDSA44();
    byte[] sig = signer.sign(MESSAGE_HASH);
    byte[] input = concat(MESSAGE_HASH, sig, other.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA44_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void mldsa44_shortInput_returnsZero() {
    byte[] tooShort = new byte[100];
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA44_ADDR).execute(tooShort);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void mldsa44_nullInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA44_ADDR).execute(null);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void mldsa65_validSignature_returnsOne() {
    MLDSA65 key = new MLDSA65();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] input = concat(MESSAGE_HASH, sig, key.getPublicKey());

    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(MLDSA65_ADDR);
    Pair<Boolean, byte[]> result = pc.execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ONE().getData(), result.getRight());
    Assert.assertEquals(7000, pc.getEnergyForData(input));
  }

  @Test
  public void mldsa65_tamperedSignature_returnsZero() {
    MLDSA65 key = new MLDSA65();
    byte[] sig = key.sign(MESSAGE_HASH);
    sig[sig.length - 1] ^= 0x01;
    byte[] input = concat(MESSAGE_HASH, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA65_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void mldsa65_shortInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA65_ADDR).execute(new byte[3000]);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  private static byte[] concat(byte[]... parts) {
    int total = 0;
    for (byte[] p : parts) {
      total += p.length;
    }
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  // Sanity check: the helper above and Arrays.copyOfRange behave consistently.
  @Test
  public void concatHelper_works() {
    byte[] a = {1, 2};
    byte[] b = {3, 4, 5};
    byte[] c = concat(a, b);
    Assert.assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, c);
    Assert.assertArrayEquals(a, Arrays.copyOfRange(c, 0, 2));
  }
}
