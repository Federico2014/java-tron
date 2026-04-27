package org.tron.common.crypto.pqc;

import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.tron.common.utils.Sha256Hash;
import org.tron.protos.Protocol.EphemeralWitness;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * Ephemeral secp256k1 PQ scheme: the on-chain "public key" is a 32-byte SHA-256
 * Merkle root committing to a fixed set of one-time secp256k1 keys. Each
 * spending transaction reveals one leaf (one-time secp256k1 pubkey), its
 * Merkle inclusion proof, and an ECDSA signature over the auth digest using
 * the corresponding one-time private key. Double-spend prevention is enforced
 * by the per-account {@code ephemeral_used_bitmap} and {@code last_ephemeral_nonce}
 * fields.
 *
 * <p>The node never holds one-time private keys — they are managed by the
 * user / wallet. As a result {@link #sign(byte[])} and the static
 * {@link #sign(byte[], byte[])} dispatch entry both throw
 * {@link UnsupportedOperationException}.
 *
 * <p>The "signature" wire bytes are the Protobuf-serialized {@link EphemeralWitness}.
 * {@link #SIGNATURE_LENGTH} is the upper bound assuming Ephemeral permissions
 * stay within 2^16 leaves (depth ≤ 16) per task C.2.2.
 */
public final class EphemeralSecp256k1 implements PqSignature {

  /** 32-byte SHA-256 Merkle root. */
  public static final int PUBLIC_KEY_LENGTH = 32;
  /**
   * Upper bound for the serialized {@link EphemeralWitness}. Based on a depth-16
   * Merkle path (16 × 32-byte siblings), uncompressed (65-byte) one-time pubkey,
   * 64-byte raw r||s ECDSA signature, plus protobuf tag/length overhead — rounded
   * up for safety.
   */
  public static final int SIGNATURE_LENGTH = 800;
  /** Maximum Merkle proof depth for Ephemeral permissions (≤ 2^16 leaves). */
  public static final int MAX_PROOF_DEPTH = 16;
  /** Compressed secp256k1 public key length (0x02/0x03 || X). */
  public static final int COMPRESSED_PUBKEY_LENGTH = 33;
  /** Uncompressed secp256k1 public key length (0x04 || X || Y). */
  public static final int UNCOMPRESSED_PUBKEY_LENGTH = 65;
  /** Raw ECDSA signature length: 32-byte big-endian r || 32-byte big-endian s. */
  public static final int ECDSA_SIGNATURE_LENGTH = 64;

  private static final X9ECParameters CURVE_PARAMS =
      CustomNamedCurves.getByName("secp256k1");
  private static final ECDomainParameters CURVE = new ECDomainParameters(
      CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
      CURVE_PARAMS.getH());
  private static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

  private final byte[] root;

  /**
   * Bind to the 32-byte PQ Merkle root that serves as this scheme's "public key".
   * The node never holds one-time secp256k1 private keys.
   */
  public EphemeralSecp256k1(byte[] root) {
    if (root == null || root.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "Ephemeral PQ root length must be " + PUBLIC_KEY_LENGTH);
    }
    this.root = root.clone();
  }

  @Override
  public SignatureScheme getScheme() {
    return SignatureScheme.EPHEMERAL_SECP256K1;
  }

  /** Ephemeral has no node-side private key; reported as 0 for interface conformance. */
  @Override
  public int getPrivateKeyLength() {
    return 0;
  }

  @Override
  public int getPublicKeyLength() {
    return PUBLIC_KEY_LENGTH;
  }

  /** Upper bound on the serialized {@link EphemeralWitness} signature. */
  @Override
  public int getSignatureLength() {
    return SIGNATURE_LENGTH;
  }

  /** Ephemeral has no node-side private key. */
  @Override
  public byte[] getPrivateKey() {
    throw new UnsupportedOperationException(
        "EPHEMERAL_SECP256K1 has no node-held private key");
  }

  @Override
  public byte[] getPublicKey() {
    return root.clone();
  }

  /**
   * Address derived from the PQ root. Mirrors the other PQ schemes
   * ({@code sha3omit12}) so account-id derivation is consistent across schemes.
   */
  @Override
  public byte[] getAddress() {
    return org.tron.common.crypto.Hash.sha3omit12(root);
  }

  /** Signing is the wallet / client's responsibility — the node does not hold one-time keys. */
  @Override
  public byte[] sign(byte[] message) {
    throw new UnsupportedOperationException(
        "EPHEMERAL_SECP256K1 signing is performed off-node by the wallet");
  }

  @Override
  public boolean verify(byte[] message, byte[] signature) {
    return verify(this.root, message, signature);
  }

  /**
   * Static verify entry used by {@link PqSignatureRegistry}.
   *
   * <p>Verification flow:
   * <ol>
   *   <li>Parse {@code signature} as {@link EphemeralWitness} bytes.</li>
   *   <li>Hash the one-time pubkey to a 32-byte leaf:
   *       {@code leaf = SHA-256(one_time_pubkey)}.</li>
   *   <li>Verify the Merkle inclusion proof against {@code publicKey} (the PQ root).</li>
   *   <li>ECDSA-verify {@code message} against the parsed one-time pubkey
   *       (no public key recovery — the pubkey is explicit).</li>
   * </ol>
   */
  public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "Ephemeral PQ root length must be " + PUBLIC_KEY_LENGTH);
    }
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    if (signature == null || signature.length == 0 || signature.length > SIGNATURE_LENGTH) {
      throw new IllegalArgumentException(
          "Ephemeral signature length must be 1.." + SIGNATURE_LENGTH);
    }

    EphemeralWitness witness;
    try {
      witness = EphemeralWitness.parseFrom(signature);
    } catch (InvalidProtocolBufferException e) {
      return false;
    }

    byte[] oneTimePubkey = witness.getOneTimePubkey().toByteArray();
    if (!isValidSecp256k1Pubkey(oneTimePubkey)) {
      return false;
    }

    int proofSize = witness.getMerklePathCount();
    if (proofSize > MAX_PROOF_DEPTH) {
      return false;
    }
    int leafIndex = witness.getLeafIndex();
    if (leafIndex < 0) {
      return false;
    }
    // leaf_index must fit in proofSize bits (i.e. < 2^proofSize).
    if (proofSize < 32 && (leafIndex >>> proofSize) != 0) {
      return false;
    }

    List<byte[]> merklePath = new ArrayList<>(proofSize);
    for (int i = 0; i < proofSize; i++) {
      byte[] sibling = witness.getMerklePath(i).toByteArray();
      if (sibling.length != MerkleTree.LEAF_LENGTH) {
        return false;
      }
      merklePath.add(sibling);
    }

    byte[] leaf = sha256(oneTimePubkey);
    if (!MerkleTree.verifyProof(publicKey, leaf, merklePath, leafIndex)) {
      return false;
    }

    byte[] ecdsaSignature = witness.getEcdsaSignature().toByteArray();
    if (ecdsaSignature.length != ECDSA_SIGNATURE_LENGTH) {
      return false;
    }
    return verifyEcdsa(oneTimePubkey, message, ecdsaSignature);
  }

  /** Signing is wallet-side; static dispatch surface kept for registry symmetry. */
  public static byte[] sign(byte[] privateKey, byte[] message) {
    throw new UnsupportedOperationException(
        "EPHEMERAL_SECP256K1 signing is performed off-node by the wallet");
  }

  /**
   * secp256k1 ECDSA verification with explicit public key (no recovery), enforcing
   * low-s canonicalization and r/s ∈ [1, n-1].
   */
  private static boolean verifyEcdsa(byte[] pubkey, byte[] message, byte[] signature) {
    BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(signature, 0, 32));
    BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(signature, 32, 64));
    if (r.signum() <= 0 || s.signum() <= 0) {
      return false;
    }
    if (r.compareTo(CURVE.getN()) >= 0 || s.compareTo(CURVE.getN()) >= 0) {
      return false;
    }
    // Reject high-s (BIP-62 / EIP-2 style malleability guard).
    if (s.compareTo(HALF_CURVE_ORDER) > 0) {
      return false;
    }
    ECPoint point;
    try {
      point = CURVE.getCurve().decodePoint(pubkey);
    } catch (RuntimeException e) {
      return false;
    }
    ECPublicKeyParameters params = new ECPublicKeyParameters(point, CURVE);
    ECDSASigner verifier = new ECDSASigner();
    verifier.init(false, params);
    try {
      return verifier.verifySignature(message, r, s);
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static boolean isValidSecp256k1Pubkey(byte[] pubkey) {
    if (pubkey == null) {
      return false;
    }
    if (pubkey.length == COMPRESSED_PUBKEY_LENGTH) {
      return pubkey[0] == 0x02 || pubkey[0] == 0x03;
    }
    if (pubkey.length == UNCOMPRESSED_PUBKEY_LENGTH) {
      return pubkey[0] == 0x04;
    }
    return false;
  }

  private static byte[] sha256(byte[] input) {
    MessageDigest md = Sha256Hash.newDigest();
    return md.digest(input);
  }
}
