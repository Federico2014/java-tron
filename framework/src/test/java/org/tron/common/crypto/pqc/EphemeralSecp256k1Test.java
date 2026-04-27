package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.Sha256Hash;
import org.tron.protos.Protocol.EphemeralWitness;
import org.tron.protos.Protocol.SignatureScheme;

public class EphemeralSecp256k1Test {

  private static final SecureRandom RNG = new SecureRandom();

  private static byte[] sha256(byte[] in) {
    MessageDigest md = Sha256Hash.newDigest();
    return md.digest(in);
  }

  /** Sign {@code digest} with {@code key} and return raw 32-byte r || 32-byte s (low-s). */
  private static byte[] rawEcdsaSign(ECKey key, byte[] digest) {
    ECKey.ECDSASignature sig = key.sign(digest).toCanonicalised();
    byte[] r = unsignedFixed(sig.r, 32);
    byte[] s = unsignedFixed(sig.s, 32);
    byte[] out = new byte[64];
    System.arraycopy(r, 0, out, 0, 32);
    System.arraycopy(s, 0, out, 32, 32);
    return out;
  }

  private static byte[] unsignedFixed(BigInteger v, int len) {
    byte[] raw = v.toByteArray();
    if (raw.length == len) {
      return raw;
    }
    if (raw.length == len + 1 && raw[0] == 0) {
      byte[] out = new byte[len];
      System.arraycopy(raw, 1, out, 0, len);
      return out;
    }
    if (raw.length < len) {
      byte[] out = new byte[len];
      System.arraycopy(raw, 0, out, len - raw.length, raw.length);
      return out;
    }
    throw new IllegalArgumentException("value does not fit in " + len + " bytes");
  }

  /** Build a fresh tree of {@code n} one-time secp256k1 keys and return all the parts. */
  private static class Tree {
    final List<ECKey> keys;
    final List<byte[]> pubkeysCompressed;
    final List<byte[]> leaves;
    final byte[] root;

    Tree(int n) {
      this.keys = new ArrayList<>();
      this.pubkeysCompressed = new ArrayList<>();
      this.leaves = new ArrayList<>();
      for (int i = 0; i < n; i++) {
        ECKey k = new ECKey(RNG);
        byte[] pk = k.getPubKeyPoint().getEncoded(true); // 33-byte compressed
        keys.add(k);
        pubkeysCompressed.add(pk);
        leaves.add(sha256(pk));
      }
      this.root = MerkleTree.buildRoot(leaves);
    }
  }

  private static byte[] buildWitness(byte[] oneTimePub, List<byte[]> path,
                                     int leafIndex, byte[] ecdsaSig) {
    EphemeralWitness.Builder b = EphemeralWitness.newBuilder()
        .setOneTimePubkey(ByteString.copyFrom(oneTimePub))
        .setLeafIndex(leafIndex)
        .setEcdsaSignature(ByteString.copyFrom(ecdsaSig));
    for (byte[] p : path) {
      b.addMerklePath(ByteString.copyFrom(p));
    }
    return b.build().toByteArray();
  }

  @Test
  public void schemeMetadata() {
    EphemeralSecp256k1 e = new EphemeralSecp256k1(new byte[32]);
    assertEquals(SignatureScheme.EPHEMERAL_SECP256K1, e.getScheme());
    assertEquals(32, e.getPublicKeyLength());
    assertEquals(0, e.getPrivateKeyLength());
    assertEquals(EphemeralSecp256k1.SIGNATURE_LENGTH, e.getSignatureLength());
  }

  @Test
  public void rejectsInvalidRootLength() {
    try {
      new EphemeralSecp256k1(new byte[31]);
      fail("31-byte root must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("32"));
    }
  }

  @Test
  public void getPrivateKeyThrows() {
    EphemeralSecp256k1 e = new EphemeralSecp256k1(new byte[32]);
    try {
      e.getPrivateKey();
      fail("Ephemeral has no node-side private key");
    } catch (UnsupportedOperationException expected) {
      // ok
    }
  }

  @Test
  public void instanceAndStaticSignBothThrow() {
    EphemeralSecp256k1 e = new EphemeralSecp256k1(new byte[32]);
    try {
      e.sign(new byte[32]);
      fail("instance sign must throw");
    } catch (UnsupportedOperationException expected) {
      // ok
    }
    try {
      EphemeralSecp256k1.sign(new byte[0], new byte[32]);
      fail("static sign must throw");
    } catch (UnsupportedOperationException expected) {
      // ok
    }
  }

  @Test
  public void publicKeyAndAddressDerivedFromRoot() {
    byte[] root = new byte[32];
    for (int i = 0; i < 32; i++) {
      root[i] = (byte) i;
    }
    EphemeralSecp256k1 e = new EphemeralSecp256k1(root);
    assertArrayEquals(root, e.getPublicKey());
    byte[] addr = e.getAddress();
    assertEquals(21, addr.length);
  }

  @Test
  public void verifyRoundTripCompressedPubkey() {
    Tree t = new Tree(8);
    int idx = 3;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, idx, sig);
    assertTrue(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyRoundTripUncompressedPubkey() {
    Tree t = new Tree(4);
    int idx = 2;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    // commit using the uncompressed leaf
    byte[] pubUncompressed = t.keys.get(idx).getPubKeyPoint().getEncoded(false);
    List<byte[]> leaves = new ArrayList<>(t.leaves);
    leaves.set(idx, sha256(pubUncompressed));
    byte[] root = MerkleTree.buildRoot(leaves);
    List<byte[]> path = MerkleTree.generateProof(leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    byte[] witness = buildWitness(pubUncompressed, path, idx, sig);
    assertTrue(EphemeralSecp256k1.verify(root, digest, witness));
  }

  @Test
  public void verifyFailsWithTamperedMerklePath() {
    Tree t = new Tree(8);
    int idx = 1;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    path.set(0, new byte[32]);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, idx, sig);
    assertFalse(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyFailsWithTamperedEcdsa() {
    Tree t = new Tree(4);
    int idx = 0;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    sig[0] ^= 0x01;
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, idx, sig);
    assertFalse(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyFailsCrossLeafReplay() {
    // Sign with key i but claim leaf index j (different one-time key). Merkle proof
    // is the legitimate path for leaf j, so SHA-256(claimed_pubkey) won't match.
    Tree t = new Tree(8);
    int legitIdx = 2;
    int spoofIdx = 5;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    // Build a path for spoofIdx but advertise the legit pubkey in the witness.
    List<byte[]> path = MerkleTree.generateProof(t.leaves, spoofIdx);
    byte[] sig = rawEcdsaSign(t.keys.get(legitIdx), digest);
    byte[] witness = buildWitness(t.pubkeysCompressed.get(legitIdx), path, spoofIdx, sig);
    assertFalse(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyFailsWithLeafIndexOutOfDepth() {
    Tree t = new Tree(4); // depth = 2, valid leaf indices 0..3
    int idx = 1;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    // Replace leaf_index with a value that exceeds the proof depth.
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, 16, sig);
    assertFalse(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyFailsWithInvalidPubkeyByte() {
    Tree t = new Tree(4);
    int idx = 0;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    // 32-byte pubkey (invalid length) - should be rejected
    byte[] witness = buildWitness(new byte[32], path, idx, sig);
    assertFalse(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyFailsWithExcessProofDepth() {
    Tree t = new Tree(4);
    int idx = 0;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    // 17 fake siblings - exceeds MAX_PROOF_DEPTH (16)
    List<byte[]> path = new ArrayList<>();
    for (int i = 0; i < 17; i++) {
      path.add(new byte[32]);
    }
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, idx, sig);
    assertFalse(EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void verifyFailsWithMalformedWitnessBytes() {
    EphemeralSecp256k1 e = new EphemeralSecp256k1(new byte[32]);
    assertFalse(e.verify(new byte[32], new byte[] {(byte) 0xff}));
  }

  @Test
  public void verifyRejectsHighSEcdsa() {
    Tree t = new Tree(2);
    int idx = 0;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest); // canonical low-s
    // Flip s to its high counterpart: s' = n - s. The verifier must reject high-s.
    BigInteger n = new BigInteger(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 32, 64));
    BigInteger highS = n.subtract(s);
    byte[] sBytes = unsignedFixed(highS, 32);
    System.arraycopy(sBytes, 0, sig, 32, 32);
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, idx, sig);
    assertFalse("high-s ECDSA must be rejected",
        EphemeralSecp256k1.verify(t.root, digest, witness));
  }

  @Test
  public void registryDispatchSucceeds() {
    Tree t = new Tree(4);
    int idx = 0;
    byte[] digest = new byte[32];
    RNG.nextBytes(digest);
    List<byte[]> path = MerkleTree.generateProof(t.leaves, idx);
    byte[] sig = rawEcdsaSign(t.keys.get(idx), digest);
    byte[] witness = buildWitness(t.pubkeysCompressed.get(idx), path, idx, sig);
    assertTrue(PqSignatureRegistry.contains(SignatureScheme.EPHEMERAL_SECP256K1));
    assertEquals(32, PqSignatureRegistry.getPublicKeyLength(SignatureScheme.EPHEMERAL_SECP256K1));
    assertTrue(PqSignatureRegistry.verify(
        SignatureScheme.EPHEMERAL_SECP256K1, t.root, digest, witness));
    assertTrue(PqSignatureRegistry.isValidSignatureLength(
        SignatureScheme.EPHEMERAL_SECP256K1, witness.length));
    assertTrue(PqSignatureRegistry.isValidSignatureLength(
        SignatureScheme.EPHEMERAL_SECP256K1, 1));
    assertFalse(PqSignatureRegistry.isValidSignatureLength(
        SignatureScheme.EPHEMERAL_SECP256K1, 0));
    assertFalse(PqSignatureRegistry.isValidSignatureLength(
        SignatureScheme.EPHEMERAL_SECP256K1, EphemeralSecp256k1.SIGNATURE_LENGTH + 1));
  }

  @Test
  public void registryFromSeedThrows() {
    try {
      PqSignatureRegistry.fromSeed(SignatureScheme.EPHEMERAL_SECP256K1, new byte[32]);
      fail("Ephemeral has no seed-keypair derivation");
    } catch (UnsupportedOperationException expected) {
      // ok
    }
  }
}
