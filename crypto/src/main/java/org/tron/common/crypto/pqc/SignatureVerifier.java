package org.tron.common.crypto.pqc;

import org.tron.protos.Protocol.SignatureScheme;

/**
 * Stateless verifier for a single post-quantum signature scheme. Independent of
 * the legacy {@code SignInterface} because PQ flows do not expose public-key
 * recovery and have no notion of node-id / private-key handling in verification
 * paths.
 */
public interface SignatureVerifier {

  SignatureScheme getScheme();

  int getPublicKeyLength();

  int getSignatureLength();

  /**
   * Verify a raw-byte signature against a raw-byte public key over {@code message}.
   * The caller SHALL pre-validate lengths via {@link #validatePublicKey(byte[])} and
   * {@link #validateSignature(byte[])}; implementations still defensively re-check.
   *
   * @return true iff the signature is cryptographically valid for the given inputs
   */
  boolean verify(byte[] publicKey, byte[] message, byte[] signature);

  default void validatePublicKey(byte[] publicKey) {
    if (publicKey == null || publicKey.length != getPublicKeyLength()) {
      throw new IllegalArgumentException(
          "invalid " + getScheme() + " public key length: "
              + (publicKey == null ? "null" : publicKey.length)
              + ", expected " + getPublicKeyLength());
    }
  }

  default void validateSignature(byte[] signature) {
    if (signature == null || signature.length != getSignatureLength()) {
      throw new IllegalArgumentException(
          "invalid " + getScheme() + " signature length: "
              + (signature == null ? "null" : signature.length)
              + ", expected " + getSignatureLength());
    }
  }
}
