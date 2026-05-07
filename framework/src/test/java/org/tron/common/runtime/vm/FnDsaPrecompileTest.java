package org.tron.common.runtime.vm;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.crypto.pqc.FNDSA;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;

/**
 * Unit tests for the FN-DSA / Falcon-512 (0x16) verify precompile (EIP-8052 / TRON extension).
 * Input layout: [msg 32B | sig_len 2B | sig sig_len B | pk 896B]. Stateless — no chain DB.
 */
public class FnDsaPrecompileTest {

  private static final DataWord FNDSA_ADDR = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000016");

  private static final byte[] MESSAGE_HASH = new byte[32];

  static {
    for (int i = 0; i < 32; i++) {
      MESSAGE_HASH[i] = (byte) i;
    }
  }

  @Before
  public void enableProposal() {
    VMConfig.initAllowFnDsa512(1L);
  }

  @After
  public void disableProposal() {
    VMConfig.initAllowFnDsa512(0L);
  }

  @Test
  public void switchOff_returnsNull() {
    VMConfig.initAllowFnDsa512(0L);
    Assert.assertNull(PrecompiledContracts.getContractForAddress(FNDSA_ADDR));
  }

  @Test
  public void switchOn_returnsContract() {
    Assert.assertNotNull(PrecompiledContracts.getContractForAddress(FNDSA_ADDR));
  }

  @Test
  public void validSignature_returnsOne() {
    FNDSA key = new FNDSA();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());

    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(FNDSA_ADDR);
    Pair<Boolean, byte[]> result = pc.execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ONE().getData(), result.getRight());
    Assert.assertEquals(2500, pc.getEnergyForData(input));
  }

  @Test
  public void tamperedMessage_returnsZero() {
    FNDSA key = new FNDSA();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] tampered = MESSAGE_HASH.clone();
    tampered[0] ^= 0x01;
    byte[] input = buildInput(tampered, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void tamperedSignature_returnsZero() {
    FNDSA key = new FNDSA();
    byte[] sig = key.sign(MESSAGE_HASH);
    sig[0] ^= 0x01;
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void wrongPublicKey_returnsZero() {
    FNDSA signer = new FNDSA();
    FNDSA other = new FNDSA();
    byte[] sig = signer.sign(MESSAGE_HASH);
    byte[] input = buildInput(MESSAGE_HASH, sig, other.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void nullInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(null);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void shortInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(new byte[100]);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void zeroSigLen_returnsZero() {
    FNDSA key = new FNDSA();
    byte[] pk = key.getPublicKey();
    // sig_len = 0 is invalid (must be >= 1)
    // input must be >= MIN_INPUT_LEN (931 = 32 + 2 + 1 + 896) to reach the sigLen check
    byte[] input = new byte[32 + 2 + pk.length + 1];
    System.arraycopy(MESSAGE_HASH, 0, input, 0, 32);
    // sig_len bytes = 0x00 0x00 → sigLen = 0
    System.arraycopy(pk, 0, input, 34, pk.length);

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void oversizedSigLen_returnsZero() {
    // sig_len = 753, which exceeds FNDSA.SIGNATURE_LENGTH (752)
    byte[] input = new byte[32 + 2 + 753 + FNDSA.PUBLIC_KEY_LENGTH];
    input[32] = 0x02;   // high byte
    input[33] = (byte) 0xF1; // low byte → 0x02F1 = 753
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void sigLenLargerThanActualData_returnsZero() {
    FNDSA key = new FNDSA();
    byte[] sig = key.sign(MESSAGE_HASH);
    // claim sig is 100 bytes longer than it is
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());
    // corrupt sig_len field to claim a larger sig
    int claimedLen = sig.length + 100;
    input[32] = (byte) ((claimedLen >> 8) & 0xFF);
    input[33] = (byte) (claimedLen & 0xFF);

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  /** Encodes input as [msg 32B | sig_len 2B | sig | pk]. */
  private static byte[] buildInput(byte[] msg, byte[] sig, byte[] pk) {
    int sigLen = sig.length;
    byte[] out = new byte[32 + 2 + sigLen + pk.length];
    System.arraycopy(msg, 0, out, 0, 32);
    out[32] = (byte) ((sigLen >> 8) & 0xFF);
    out[33] = (byte) (sigLen & 0xFF);
    System.arraycopy(sig, 0, out, 34, sigLen);
    System.arraycopy(pk, 0, out, 34 + sigLen, pk.length);
    return out;
  }
}
