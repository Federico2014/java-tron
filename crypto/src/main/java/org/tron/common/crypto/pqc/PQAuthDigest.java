package org.tron.common.crypto.pqc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.tron.common.utils.Sha256Hash;

/**
 * Domain-separated SHA-256 digests for post-quantum authentication.
 *
 * <p>The domain prefixes are UTF-8 string bytes concatenated before the
 * context fields. They differ between transaction and block flows so a
 * transaction signature can never be replayed as a block signature and vice
 * versa.
 *
 * <p><b>V2.</b> Address-as-fingerprint binding (0x41 ‖ deriveHash(pk)[12..32])
 * makes the signing key uniquely identifiable from the witness public_key
 * itself, so the digest no longer needs to bind a {@code key_id}. The
 * permission_id is still bound for transactions because it selects which
 * permission's keys[] is consulted.
 */
public final class PQAuthDigest {

  public static final String TX_DOMAIN = "TRON_TX_AUTH_V1";
  public static final String BLOCK_DOMAIN = "TRON_BLOCK_AUTH_V1";

  private static final byte[] TX_DOMAIN_BYTES = TX_DOMAIN.getBytes(StandardCharsets.UTF_8);
  private static final byte[] BLOCK_DOMAIN_BYTES = BLOCK_DOMAIN.getBytes(StandardCharsets.UTF_8);

  private PQAuthDigest() {
  }

  /**
   * Transaction-level PQ authentication digest.
   *
   * <pre>digest = SHA-256("TRON_TX_AUTH_V1" || txid || permission_id_be4)</pre>
   */
  public static byte[] tx(byte[] txid, int permissionId) {
    requireNonNull(txid, "txid");
    MessageDigest md = Sha256Hash.newDigest();
    md.update(TX_DOMAIN_BYTES);
    md.update(txid);
    md.update(intToBe4(permissionId));
    return md.digest();
  }

  /**
   * Block-level PQ authentication digest.
   *
   * <pre>digest = SHA-256("TRON_BLOCK_AUTH_V1" || block_header_raw_hash)</pre>
   */
  public static byte[] block(byte[] blockHeaderRawHash) {
    requireNonNull(blockHeaderRawHash, "blockHeaderRawHash");
    MessageDigest md = Sha256Hash.newDigest();
    md.update(BLOCK_DOMAIN_BYTES);
    md.update(blockHeaderRawHash);
    return md.digest();
  }

  private static byte[] intToBe4(int v) {
    return new byte[] {
        (byte) ((v >>> 24) & 0xff),
        (byte) ((v >>> 16) & 0xff),
        (byte) ((v >>> 8) & 0xff),
        (byte) (v & 0xff)
    };
  }

  static void requireNonNull(byte[] b, String name) {
    if (b == null) {
      throw new IllegalArgumentException(name + " must not be null");
    }
  }
}
