package org.tron.common.crypto.pqc;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.tron.common.crypto.Hash;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * FIPS 204 ML-DSA-65 keypair-bound signer/verifier. Instance verify and sign
 * use the bound keypair; stateless dispatch is available via the static
 * {@link #verify} / {@link #sign(byte[], byte[])} entry points and the
 * {@link PqSignatureRegistry}. Consumes raw public key / signature bytes —
 * no SubjectPublicKeyInfo, PEM, or Base64 wrapping.
 */
public final class MLDSA65 implements PqSignature {

  public static final int PRIVATE_KEY_LENGTH = 4032;
  public static final int PUBLIC_KEY_LENGTH = 1952;
  public static final int SIGNATURE_LENGTH = 3309;
  /** FIPS 204 ML-DSA seed (ξ) is 32 bytes. */
  public static final int SEED_LENGTH = 32;

  private final byte[] privateKey;
  private final byte[] publicKey;

  /** Generate a fresh keypair using a cryptographically secure random source. */
  public MLDSA65() {
    this.privateKey = generatePrivateKey();
    this.publicKey = derivePublicKey(this.privateKey);
  }

  /** Deterministically generate a keypair from a 32-byte seed (FIPS 204 ξ). */
  public MLDSA65(byte[] seed) {
    if (seed == null || seed.length != SEED_LENGTH) {
      throw new IllegalArgumentException("ML-DSA-65 seed length must be " + SEED_LENGTH);
    }
    this.privateKey = generatePrivateKeyFromSeed(seed);
    this.publicKey = derivePublicKey(this.privateKey);
  }

  /**
   * Build a keypair-bound instance from an existing keypair without re-deriving the public key.
   * The caller is responsible for ensuring that {@code publicKey} is the correct public key
   * corresponding to {@code privateKey}; no consistency check is performed.
   */
  public MLDSA65(byte[] privateKey, byte[] publicKey) {
    validatePrivateKeyBytes(privateKey);
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 public key length must be " + PUBLIC_KEY_LENGTH);
    }
    this.privateKey = privateKey.clone();
    this.publicKey = publicKey.clone();
  }

  /** Load an existing 4032-byte ML-DSA-65 private key; the public key is derived. */
  public static MLDSA65 fromPrivate(byte[] privateKey) {
    validatePrivateKeyBytes(privateKey);
    byte[] sk = privateKey.clone();
    return new MLDSA65(sk, derivePublicKey(sk));
  }

  @Override
  public SignatureScheme getScheme() {
    return SignatureScheme.ML_DSA_65;
  }

  @Override
  public int getPrivateKeyLength() {
    return PRIVATE_KEY_LENGTH;
  }

  @Override
  public int getPublicKeyLength() {
    return PUBLIC_KEY_LENGTH;
  }

  @Override
  public int getSignatureLength() {
    return SIGNATURE_LENGTH;
  }

  @Override
  public byte[] getPrivateKey() {
    return privateKey.clone();
  }

  @Override
  public byte[] getPublicKey() {
    return publicKey.clone();
  }

  /** 21-byte TRON address derived from the public key. */
  @Override
  public byte[] getAddress() {
    return Hash.sha3omit12(publicKey);
  }

  @Override
  public byte[] sign(byte[] message) {
    return sign(privateKey, message);
  }

  @Override
  public boolean verify(byte[] message, byte[] signature) {
    return verify(publicKey, message, signature);
  }

  public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 public key length must be " + PUBLIC_KEY_LENGTH);
    }
    if (signature == null || signature.length != SIGNATURE_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 signature length must be " + SIGNATURE_LENGTH);
    }
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    MLDSAPublicKeyParameters pk = new MLDSAPublicKeyParameters(
        MLDSAParameters.ml_dsa_65, publicKey);
    MLDSASigner verifier = new MLDSASigner();
    verifier.init(false, pk);
    verifier.update(message, 0, message.length);
    return verifier.verifySignature(signature);
  }

  public static byte[] sign(byte[] privateKey, byte[] message) {
    validatePrivateKeyBytes(privateKey);
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(
        MLDSAParameters.ml_dsa_65, privateKey);
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, sk);
    signer.update(message, 0, message.length);
    try {
      return signer.generateSignature();
    } catch (Exception e) {
      throw new IllegalStateException("ML-DSA-65 signing failed", e);
    }
  }

  /** Generate a fresh ML-DSA-65 private key; returns the NIST-encoded 4032-byte key. */
  public static byte[] generatePrivateKey() {
    return generatePrivateKey(new SecureRandom());
  }

  /** Deterministically generate an ML-DSA-65 private key from a 32-byte seed. */
  public static byte[] generatePrivateKeyFromSeed(byte[] seed) {
    if (seed == null || seed.length != SEED_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 seed length must be " + SEED_LENGTH);
    }
    return generatePrivateKey(new FixedSecureRandom(seed));
  }

  private static byte[] generatePrivateKey(SecureRandom random) {
    MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
    generator.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65));
    AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
    return ((MLDSAPrivateKeyParameters) keyPair.getPrivate()).getEncoded();
  }

  public static byte[] derivePublicKey(byte[] privateKey) {
    validatePrivateKeyBytes(privateKey);
    MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(
        MLDSAParameters.ml_dsa_65, privateKey);
    MLDSAPublicKeyParameters pk = sk.getPublicKeyParameters();
    return pk.getEncoded();
  }

  /** Derive a TRON 21-byte address from an ML-DSA-65 public key via {@code sha3omit12(pubKey)}. */
  public static byte[] computeAddress(byte[] publicKey) {
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 public key length must be " + PUBLIC_KEY_LENGTH);
    }
    return Hash.sha3omit12(publicKey);
  }

  private static void validatePrivateKeyBytes(byte[] privateKey) {
    if (privateKey == null || privateKey.length != PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 private key length must be " + PRIVATE_KEY_LENGTH);
    }
  }
}
