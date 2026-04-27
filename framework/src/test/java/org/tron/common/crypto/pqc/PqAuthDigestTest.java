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
    assertEquals("TRON_EPHEMERAL_TX_AUTH_V1", PqAuthDigest.EPHEMERAL_TX_DOMAIN);
  }

  @Test
  public void ephemeralTxDigestEqualsExpectedSha256() throws Exception {
    byte[] txid = bytes(0x11, 0x22, 0x33, 0x44);
    int permissionId = 5;
    byte[] signer = bytes(0xaa, 0xbb, 0xcc);
    long nonce = 0x0102030405060708L;
    int leafIndex = 0xCAFEBABE;

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update("TRON_EPHEMERAL_TX_AUTH_V1".getBytes(StandardCharsets.UTF_8));
    md.update(txid);
    md.update(bytes(0, 0, 0, 5));
    md.update(signer);
    md.update(bytes(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08));
    md.update(bytes(0xCA, 0xFE, 0xBA, 0xBE));
    byte[] expected = md.digest();

    byte[] actual = PqAuthDigest.ephemeralTx(txid, permissionId, signer, nonce, leafIndex);
    assertArrayEquals(expected, actual);
    assertEquals(32, actual.length);
  }

  @Test
  public void ephemeralTxDistinctFromTxDigest() {
    byte[] txid = new byte[32];
    byte[] addr = new byte[] {1, 2, 3};
    byte[] tx = PqAuthDigest.tx(txid, 1, addr);
    byte[] eph = PqAuthDigest.ephemeralTx(txid, 1, addr, 0L, 0);
    assertFalse("ephemeralTx must not collide with tx",
        java.util.Arrays.equals(tx, eph));
  }

  @Test
  public void ephemeralTxNonceChangesDigest() {
    byte[] txid = new byte[32];
    byte[] addr = new byte[] {1};
    byte[] d0 = PqAuthDigest.ephemeralTx(txid, 0, addr, 0L, 0);
    byte[] d1 = PqAuthDigest.ephemeralTx(txid, 0, addr, 1L, 0);
    assertNotEquals(new String(d0), new String(d1));
  }

  @Test
  public void ephemeralTxLeafIndexChangesDigest() {
    byte[] txid = new byte[32];
    byte[] addr = new byte[] {1};
    byte[] d0 = PqAuthDigest.ephemeralTx(txid, 0, addr, 0L, 0);
    byte[] d1 = PqAuthDigest.ephemeralTx(txid, 0, addr, 0L, 1);
    assertNotEquals(new String(d0), new String(d1));
  }

  @Test
  public void ephemeralTxAcceptsFullUint32Range() {
    // Proto uint32 maps to Java int; negative-as-signed values are valid wire indices.
    byte[] hi = PqAuthDigest.ephemeralTx(new byte[32], 0, new byte[1], 0L, 0xFFFFFFFF);
    byte[] zero = PqAuthDigest.ephemeralTx(new byte[32], 0, new byte[1], 0L, 0);
    assertNotEquals(new String(hi), new String(zero));
  }

  @Test
  public void ephemeralTxNullInputsRejected() {
    try {
      PqAuthDigest.ephemeralTx(null, 0, new byte[1], 0L, 0);
      fail("null txid must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("txid"));
    }
    try {
      PqAuthDigest.ephemeralTx(new byte[1], 0, null, 0L, 0);
      fail("null signer must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signerAddress"));
    }
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
