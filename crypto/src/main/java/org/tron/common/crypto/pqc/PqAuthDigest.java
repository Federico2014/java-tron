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
 */
public final class PqAuthDigest {

  public static final String TX_DOMAIN = "TRON_TX_AUTH_V1";
  public static final String BLOCK_DOMAIN = "TRON_BLOCK_AUTH_V1";

  static final byte[] TX_DOMAIN_BYTES = TX_DOMAIN.getBytes(StandardCharsets.UTF_8);
  static final byte[] BLOCK_DOMAIN_BYTES = BLOCK_DOMAIN.getBytes(StandardCharsets.UTF_8);

  private PqAuthDigest() {
  }

  /**
   * Transaction-level PQ authentication digest.
   *
   * <pre>digest = SHA-256("TRON_TX_AUTH_V1" || txid || permission_id_be4 || signer_address)</pre>
   */
  public static byte[] tx(byte[] txid, int permissionId, byte[] signerAddress) {
    requireNonNull(txid, "txid");
    requireNonNull(signerAddress, "signerAddress");
    MessageDigest md = Sha256Hash.newDigest();
    md.update(TX_DOMAIN_BYTES);
    md.update(txid);
    md.update(intToBe4(permissionId));
    md.update(signerAddress);
    return md.digest();
  }

  /**
   * Block-level PQ authentication digest.
   *
   * <pre>digest = SHA-256("TRON_BLOCK_AUTH_V1" || block_header_raw_hash || witness_address)</pre>
   */
  public static byte[] block(byte[] blockHeaderRawHash, byte[] witnessAddress) {
    requireNonNull(blockHeaderRawHash, "blockHeaderRawHash");
    requireNonNull(witnessAddress, "witnessAddress");
    MessageDigest md = Sha256Hash.newDigest();
    md.update(BLOCK_DOMAIN_BYTES);
    md.update(blockHeaderRawHash);
    md.update(witnessAddress);
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

  private static void requireNonNull(byte[] b, String name) {
    if (b == null) {
      throw new IllegalArgumentException(name + " must not be null");
    }
  }
}
