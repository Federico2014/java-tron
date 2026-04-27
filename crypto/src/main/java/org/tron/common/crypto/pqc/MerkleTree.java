package org.tron.common.crypto.pqc;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import org.tron.common.utils.Sha256Hash;

/**
 * SHA-256 binary Merkle tree for PQ ephemeral key commitments.
 *
 * <p>Leaves are 32-byte hashes supplied by the caller (typically
 * {@code SHA-256(one_time_pubkey)}). The leaf count must be a power of two and
 * {@code >= 1}; the caller pads with a domain-specific sentinel if needed.
 * Internal nodes use the Bitcoin-style concatenation:
 * <pre>parent = SHA-256(left || right)</pre>
 *
 * <p>Proofs are ordered bottom-up: {@code proof[0]} is the sibling at the leaf
 * level, {@code proof[depth-1]} is the sibling adjacent to the root. The leaf
 * index encodes left/right at each level (bit 0 = leaf level, bit {@code depth-1}
 * = top level).
 *
 * <p>Tree depth is capped at {@link #MAX_DEPTH} (2^32 leaves) so a single proof
 * fits in a fixed buffer; Phase C constrains usage to {@code <= 2^16} leaves
 * per Ephemeral permission via the account bitmap, but the tree itself does
 * not enforce that lower bound.
 */
public final class MerkleTree {

  public static final int LEAF_LENGTH = 32;
  public static final int MAX_DEPTH = 32;

  private MerkleTree() {
  }

  /**
   * Build the Merkle root from {@code leaves}.
   *
   * @param leaves non-empty, power-of-two-sized list of 32-byte leaf hashes
   * @return 32-byte SHA-256 Merkle root
   */
  public static byte[] buildRoot(List<byte[]> leaves) {
    validateLeaves(leaves);
    byte[][] level = copyLeaves(leaves);
    while (level.length > 1) {
      level = nextLevel(level);
    }
    return level[0];
  }

  /**
   * Generate the inclusion proof for the leaf at {@code index}.
   *
   * @param leaves non-empty, power-of-two-sized list of 32-byte leaf hashes
   * @param index 0-based leaf index
   * @return ordered list of {@code log2(leaves.size())} sibling hashes
   */
  public static List<byte[]> generateProof(List<byte[]> leaves, int index) {
    validateLeaves(leaves);
    if (index < 0 || index >= leaves.size()) {
      throw new IllegalArgumentException(
          "leaf index out of range: " + index + ", size=" + leaves.size());
    }
    byte[][] level = copyLeaves(leaves);
    List<byte[]> proof = new ArrayList<>();
    int idx = index;
    while (level.length > 1) {
      int siblingIdx = idx ^ 1;
      proof.add(level[siblingIdx].clone());
      level = nextLevel(level);
      idx >>>= 1;
    }
    return proof;
  }

  /**
   * Verify that {@code leaf} occupies position {@code index} under {@code root}.
   *
   * @param root expected 32-byte Merkle root
   * @param leaf 32-byte leaf hash being proven
   * @param proof ordered sibling hashes from leaf level upward
   * @param index 0-based leaf index encoding left/right at each level
   * @return true iff the proof recomputes to {@code root}
   */
  public static boolean verifyProof(byte[] root, byte[] leaf, List<byte[]> proof, int index) {
    if (root == null || root.length != LEAF_LENGTH) {
      throw new IllegalArgumentException("root must be " + LEAF_LENGTH + " bytes");
    }
    if (leaf == null || leaf.length != LEAF_LENGTH) {
      throw new IllegalArgumentException("leaf must be " + LEAF_LENGTH + " bytes");
    }
    if (proof == null) {
      throw new IllegalArgumentException("proof must not be null");
    }
    int depth = proof.size();
    if (depth > MAX_DEPTH) {
      throw new IllegalArgumentException("proof depth exceeds " + MAX_DEPTH);
    }
    if (index < 0) {
      throw new IllegalArgumentException("leaf index must be non-negative");
    }
    // Index must fit in `depth` bits (leaf range = [0, 2^depth)).
    if (depth < 32 && (index >>> depth) != 0) {
      throw new IllegalArgumentException(
          "leaf index " + index + " exceeds depth " + depth);
    }
    byte[] node = leaf.clone();
    for (int i = 0; i < depth; i++) {
      byte[] sibling = proof.get(i);
      if (sibling == null || sibling.length != LEAF_LENGTH) {
        throw new IllegalArgumentException("proof[" + i + "] must be " + LEAF_LENGTH + " bytes");
      }
      boolean rightChild = ((index >>> i) & 1) == 1;
      node = rightChild ? hashPair(sibling, node) : hashPair(node, sibling);
    }
    return constantTimeEquals(node, root);
  }

  private static void validateLeaves(List<byte[]> leaves) {
    if (leaves == null || leaves.isEmpty()) {
      throw new IllegalArgumentException("leaves must not be null or empty");
    }
    int n = leaves.size();
    if ((n & (n - 1)) != 0) {
      throw new IllegalArgumentException("leaf count must be a power of two: " + n);
    }
    int depth = Integer.numberOfTrailingZeros(n);
    if (depth > MAX_DEPTH) {
      throw new IllegalArgumentException("tree depth exceeds " + MAX_DEPTH);
    }
    for (int i = 0; i < n; i++) {
      byte[] leaf = leaves.get(i);
      if (leaf == null || leaf.length != LEAF_LENGTH) {
        throw new IllegalArgumentException(
            "leaves[" + i + "] must be " + LEAF_LENGTH + " bytes");
      }
    }
  }

  private static byte[][] copyLeaves(List<byte[]> leaves) {
    byte[][] out = new byte[leaves.size()][];
    for (int i = 0; i < leaves.size(); i++) {
      out[i] = leaves.get(i).clone();
    }
    return out;
  }

  private static byte[][] nextLevel(byte[][] current) {
    byte[][] next = new byte[current.length / 2][];
    for (int i = 0; i < next.length; i++) {
      next[i] = hashPair(current[2 * i], current[2 * i + 1]);
    }
    return next;
  }

  private static byte[] hashPair(byte[] left, byte[] right) {
    MessageDigest md = Sha256Hash.newDigest();
    md.update(left);
    md.update(right);
    return md.digest();
  }

  private static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    int diff = 0;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
