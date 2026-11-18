package org.tron.common.crypto;

import java.security.MessageDigest;
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
