package org.tron.common.crypto;

import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class Blake2bfMessageDigestTest {

  @Test
  public void testFailedDigestDoesNotTaintState() throws Exception {
    byte[] input = new byte[Blake2bfMessageDigest.Blake2bfDigest.MESSAGE_LENGTH_BYTES];
    input[3] = 12;   // rounds
    input[212] = 1;  // final block flag

    byte[] expected = digest(input);

    MessageDigest digest = new Blake2bfMessageDigest();
    digest.update(input);
    try {
      digest.digest(new byte[32], -32, 64);
      Assert.fail("Expected the undersized output buffer to be rejected");
    } catch (IllegalArgumentException expectedFailure) {
      // the output buffer is too small, so digesting must fail before touching the state
    }

    Assert.assertArrayEquals(expected, digest.digest());
  }

  @Test
  public void testDigestHonorsOutputOffset() throws Exception {
    byte[] input = new byte[Blake2bfMessageDigest.Blake2bfDigest.MESSAGE_LENGTH_BYTES];
    input[3] = 12;   // rounds
    input[212] = 1;  // final block flag
    byte[] expected = digest(input);

    int offset = 16;
    byte[] out = new byte[offset + expected.length + 8];
    Arrays.fill(out, (byte) 0x5A);

    MessageDigest digest = new Blake2bfMessageDigest();
    digest.update(input);

    Assert.assertEquals(64, digest.digest(out, offset, 64));
    Assert.assertArrayEquals(expected, Arrays.copyOfRange(out, offset, offset + 64));
    for (int i = 0; i < out.length; i++) {
      if (i < offset || i >= offset + 64) {
        Assert.assertEquals(0x5A, out[i] & 0xFF);
      }
    }
  }

  @Test
  public void testCloneIsNotSupported() throws Exception {
    MessageDigest digest = new Blake2bfMessageDigest();
    try {
      digest.clone();
      Assert.fail("Expected cloning to be unsupported");
    } catch (CloneNotSupportedException expectedFailure) {
      // the digest deliberately does not implement Cloneable
    }
  }

  private byte[] digest(byte[] input) {
    MessageDigest digest = new Blake2bfMessageDigest();
    digest.update(input);
    return digest.digest();
  }
}
