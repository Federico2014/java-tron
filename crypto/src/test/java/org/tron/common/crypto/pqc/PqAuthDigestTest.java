package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.Test;

public class PqAuthDigestTest {

  private static byte[] bytes(int... values) {
    byte[] out = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      out[i] = (byte) values[i];
    }
    return out;
  }

  @Test
  public void txDigestEqualsExpectedSha256() throws Exception {
    byte[] txid = bytes(0x11, 0x22, 0x33, 0x44);
    int permissionId = 2;
    byte[] signer = bytes(0xaa, 0xbb, 0xcc);

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update("TRON_TX_AUTH_V1".getBytes(StandardCharsets.UTF_8));
    md.update(txid);
    md.update(bytes(0, 0, 0, 2));
    md.update(signer);
    byte[] expected = md.digest();

    byte[] actual = PqAuthDigest.tx(txid, permissionId, signer);
    assertArrayEquals(expected, actual);
    assertEquals(32, actual.length);
  }

  @Test
  public void blockDigestEqualsExpectedSha256() throws Exception {
    byte[] hdrHash = new byte[32];
    for (int i = 0; i < hdrHash.length; i++) {
      hdrHash[i] = (byte) i;
    }
    byte[] witness = bytes(0x41, 0x42, 0x43);

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update("TRON_BLOCK_AUTH_V1".getBytes(StandardCharsets.UTF_8));
    md.update(hdrHash);
    md.update(witness);
    byte[] expected = md.digest();

    byte[] actual = PqAuthDigest.block(hdrHash, witness);
    assertArrayEquals(expected, actual);
    assertEquals(32, actual.length);
  }

  @Test
  public void txAndBlockDigestsDifferForSameContext() {
    byte[] shared = new byte[32];
    byte[] addr = new byte[] {1, 2, 3, 4, 5};
    byte[] txDigest = PqAuthDigest.tx(shared, 0, addr);
    byte[] blockDigest = PqAuthDigest.block(shared, addr);
    assertFalse("tx and block digests must not collide for shared inputs",
        java.util.Arrays.equals(txDigest, blockDigest));
  }

  @Test
  public void differentSignersProduceDifferentTxDigest() {
    byte[] txid = new byte[32];
    byte[] a = new byte[] {0x10};
    byte[] b = new byte[] {0x20};
    assertNotEquals(
        new String(PqAuthDigest.tx(txid, 0, a)),
        new String(PqAuthDigest.tx(txid, 0, b)));
  }

  @Test
  public void differentPermissionIdsProduceDifferentDigest() {
    byte[] txid = new byte[32];
    byte[] addr = new byte[] {1};
    byte[] d0 = PqAuthDigest.tx(txid, 0, addr);
    byte[] d1 = PqAuthDigest.tx(txid, 1, addr);
    assertFalse(java.util.Arrays.equals(d0, d1));
  }

  @Test
  public void differentWitnessesProduceDifferentBlockDigest() {
    byte[] hdr = new byte[32];
    byte[] w1 = new byte[] {1};
    byte[] w2 = new byte[] {2};
    byte[] d1 = PqAuthDigest.block(hdr, w1);
    byte[] d2 = PqAuthDigest.block(hdr, w2);
    assertFalse(java.util.Arrays.equals(d1, d2));
  }

  @Test
  public void domainPrefixesAreExact() {
    assertEquals("TRON_TX_AUTH_V1", PqAuthDigest.TX_DOMAIN);
    assertEquals("TRON_BLOCK_AUTH_V1", PqAuthDigest.BLOCK_DOMAIN);
  }

  @Test
  public void nullInputsRejected() {
    try {
      PqAuthDigest.tx(null, 0, new byte[1]);
      fail("null txid should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("txid"));
    }
    try {
      PqAuthDigest.tx(new byte[1], 0, null);
      fail("null signer should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signerAddress"));
    }
    try {
      PqAuthDigest.block(null, new byte[1]);
      fail("null hdr should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("blockHeaderRawHash"));
    }
    try {
      PqAuthDigest.block(new byte[1], null);
      fail("null witness should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("witnessAddress"));
    }
  }
}
