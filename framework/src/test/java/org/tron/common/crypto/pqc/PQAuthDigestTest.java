package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.Test;

public class PQAuthDigestTest {

  private static byte[] be4(int v) {
    return new byte[] {
        (byte) ((v >>> 24) & 0xff),
        (byte) ((v >>> 16) & 0xff),
        (byte) ((v >>> 8) & 0xff),
        (byte) (v & 0xff)
    };
  }

  @Test
  public void txDigestEqualsExpectedSha256() throws Exception {
    byte[] txid = new byte[] {0x11, 0x22, 0x33, 0x44};
    int permissionId = 2;

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update("TRON_TX_AUTH_V1".getBytes(StandardCharsets.UTF_8));
    md.update(txid);
    md.update(be4(permissionId));
    byte[] expected = md.digest();

    byte[] actual = PQAuthDigest.tx(txid, permissionId);
    assertArrayEquals(expected, actual);
    assertEquals(32, actual.length);
  }

  @Test
  public void blockDigestEqualsExpectedSha256() throws Exception {
    byte[] hdrHash = new byte[32];
    for (int i = 0; i < hdrHash.length; i++) {
      hdrHash[i] = (byte) i;
    }

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update("TRON_BLOCK_AUTH_V1".getBytes(StandardCharsets.UTF_8));
    md.update(hdrHash);
    byte[] expected = md.digest();

    byte[] actual = PQAuthDigest.block(hdrHash);
    assertArrayEquals(expected, actual);
    assertEquals(32, actual.length);
  }

  @Test
  public void txAndBlockDigestsDifferForSameContext() {
    byte[] shared = new byte[32];
    byte[] txDigest = PQAuthDigest.tx(shared, 0);
    byte[] blockDigest = PQAuthDigest.block(shared);
    assertFalse("tx and block digests must not collide for shared inputs",
        java.util.Arrays.equals(txDigest, blockDigest));
  }

  @Test
  public void differentPermissionIdsProduceDifferentDigest() {
    byte[] txid = new byte[32];
    byte[] d0 = PQAuthDigest.tx(txid, 0);
    byte[] d1 = PQAuthDigest.tx(txid, 1);
    assertFalse(java.util.Arrays.equals(d0, d1));
  }

  @Test
  public void domainPrefixesAreExact() {
    assertEquals("TRON_TX_AUTH_V1", PQAuthDigest.TX_DOMAIN);
    assertEquals("TRON_BLOCK_AUTH_V1", PQAuthDigest.BLOCK_DOMAIN);
  }

  @Test
  public void nullTxidRejected() {
    try {
      PQAuthDigest.tx(null, 0);
      fail("null txid should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("txid"));
    }
  }

  @Test
  public void nullBlockHeaderHashRejected() {
    try {
      PQAuthDigest.block(null);
      fail("null blockHeaderRawHash should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("blockHeaderRawHash"));
    }
  }
}
