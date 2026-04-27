package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.Test;
import org.tron.common.utils.Sha256Hash;

public class MerkleTreeTest {

  private static byte[] leaf(int seed) {
    byte[] buf = new byte[MerkleTree.LEAF_LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = (byte) (seed + i);
    }
    return buf;
  }

  private static byte[] hashPair(byte[] l, byte[] r) {
    MessageDigest md = Sha256Hash.newDigest();
    md.update(l);
    md.update(r);
    return md.digest();
  }

  private static List<byte[]> leaves(int n) {
    List<byte[]> out = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      out.add(leaf(i));
    }
    return out;
  }

  @Test
  public void singleLeafRootEqualsLeaf() {
    byte[] only = leaf(7);
    byte[] root = MerkleTree.buildRoot(Collections.singletonList(only));
    assertArrayEquals(only, root);
  }

  @Test
  public void twoLeafRootMatchesManualHash() {
    byte[] l0 = leaf(0);
    byte[] l1 = leaf(1);
    byte[] expected = hashPair(l0, l1);
    byte[] root = MerkleTree.buildRoot(java.util.Arrays.asList(l0, l1));
    assertArrayEquals(expected, root);
  }

  @Test
  public void fourLeafRootMatchesManualHash() {
    List<byte[]> ls = leaves(4);
    byte[] h01 = hashPair(ls.get(0), ls.get(1));
    byte[] h23 = hashPair(ls.get(2), ls.get(3));
    byte[] expected = hashPair(h01, h23);
    assertArrayEquals(expected, MerkleTree.buildRoot(ls));
  }

  @Test
  public void proofVerifiesAtEveryIndex() {
    int n = 16;
    List<byte[]> ls = leaves(n);
    byte[] root = MerkleTree.buildRoot(ls);
    for (int i = 0; i < n; i++) {
      List<byte[]> proof = MerkleTree.generateProof(ls, i);
      assertEquals(4, proof.size());
      assertTrue("proof must verify for leaf " + i,
          MerkleTree.verifyProof(root, ls.get(i), proof, i));
    }
  }

  @Test
  public void proofRejectsWrongIndex() {
    List<byte[]> ls = leaves(8);
    byte[] root = MerkleTree.buildRoot(ls);
    List<byte[]> proof = MerkleTree.generateProof(ls, 3);
    assertFalse(MerkleTree.verifyProof(root, ls.get(3), proof, 4));
  }

  @Test
  public void proofRejectsTamperedSibling() {
    List<byte[]> ls = leaves(8);
    byte[] root = MerkleTree.buildRoot(ls);
    List<byte[]> proof = MerkleTree.generateProof(ls, 5);
    proof.get(0)[0] ^= 0x01;
    assertFalse(MerkleTree.verifyProof(root, ls.get(5), proof, 5));
  }

  @Test
  public void proofRejectsWrongLeaf() {
    List<byte[]> ls = leaves(8);
    byte[] root = MerkleTree.buildRoot(ls);
    List<byte[]> proof = MerkleTree.generateProof(ls, 2);
    byte[] wrong = leaf(99);
    assertFalse(MerkleTree.verifyProof(root, wrong, proof, 2));
  }

  @Test
  public void proofDepthMatchesLog2OfLeafCount() {
    int[] sizes = {1, 2, 4, 8, 16, 256, 65536};
    for (int n : sizes) {
      List<byte[]> ls = leaves(n);
      List<byte[]> proof = MerkleTree.generateProof(ls, 0);
      assertEquals("depth for n=" + n, Integer.numberOfTrailingZeros(n), proof.size());
    }
  }

  @Test
  public void powerOfTwoEnforced() {
    try {
      MerkleTree.buildRoot(leaves(3));
      fail("non-power-of-two leaf count should throw");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("power of two"));
    }
  }

  @Test
  public void emptyLeavesRejected() {
    try {
      MerkleTree.buildRoot(Collections.emptyList());
      fail("empty leaves should throw");
    } catch (IllegalArgumentException expected) {
      // ok
    }
  }

  @Test
  public void wrongLeafLengthRejected() {
    try {
      MerkleTree.buildRoot(Collections.singletonList(new byte[31]));
      fail("31-byte leaf should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("32"));
    }
  }

  @Test
  public void verifyRejectsWrongRoot() {
    List<byte[]> ls = leaves(4);
    byte[] root = MerkleTree.buildRoot(ls);
    List<byte[]> proof = MerkleTree.generateProof(ls, 1);
    byte[] wrongRoot = root.clone();
    wrongRoot[0] ^= 0x01;
    assertFalse(MerkleTree.verifyProof(wrongRoot, ls.get(1), proof, 1));
  }

  @Test
  public void verifyRejectsIndexOutOfDepth() {
    List<byte[]> ls = leaves(4);
    byte[] root = MerkleTree.buildRoot(ls);
    List<byte[]> proof = MerkleTree.generateProof(ls, 1);
    try {
      // proof depth = 2, valid indices 0..3; index 4 has bit 2 set -> rejected
      MerkleTree.verifyProof(root, ls.get(1), proof, 4);
      fail("index out of depth should throw");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("exceeds depth"));
    }
  }

  @Test
  public void depth16Stress() {
    int n = 1 << 16;
    List<byte[]> ls = leaves(n);
    byte[] root = MerkleTree.buildRoot(ls);
    int[] sample = {0, 1, 7, 1234, 32767, 32768, 65534, 65535};
    for (int idx : sample) {
      List<byte[]> proof = MerkleTree.generateProof(ls, idx);
      assertEquals(16, proof.size());
      assertTrue("idx=" + idx, MerkleTree.verifyProof(root, ls.get(idx), proof, idx));
    }
  }
}
