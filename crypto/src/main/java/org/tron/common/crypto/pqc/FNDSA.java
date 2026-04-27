package org.tron.common.crypto.pqc;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.tron.common.crypto.Hash;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * FIPS 206 (draft) FN-DSA / Falcon-512 keypair-bound signer/verifier. Mirrors the
 * {@link MLDSA44} / {@link MLDSA65} / {@link SLHDSA} shape: instance methods sign/verify
 * with the bound keypair, static {@link #sign(byte[], byte[])} / {@link #verify} provide
 * stateless entry points used by {@link PqSignatureRegistry}.
 *
 * <p>Falcon signatures are <strong>variable-length</strong>: {@link #SIGNATURE_LENGTH} is
 * the protocol-level upper bound, not an exact length. The {@link PqSignature#validateSignature}
 * default treats this as {@code <= SIGNATURE_LENGTH}; ML-DSA / SLH-DSA override back to
 * strict equality. BouncyCastle 1.79's {@code FalconNIST.CRYPTO_BYTES} for Falcon-512 is
 * 690 bytes, well below the 752-byte protocol cap.
 */
public final class FNDSA implements PqSignature {

  /**
   * Falcon-512 encoded private key from BC: f || g || F, where f and g are each
   * {@link #F_G_ENCODED_LENGTH} bytes (6 bits per coefficient × N=512 / 8) and F is
   * {@link #BIG_F_ENCODED_LENGTH} bytes (8 bits per coefficient × N=512 / 8).
   */
  public static final int F_G_ENCODED_LENGTH = 384;
  public static final int BIG_F_ENCODED_LENGTH = 512;
  public static final int PRIVATE_KEY_LENGTH =
      F_G_ENCODED_LENGTH + F_G_ENCODED_LENGTH + BIG_F_ENCODED_LENGTH;
  /**
   * Falcon-512 public key from BC: 14 * N / 8 = 896 bytes (the modq-encoded h polynomial).
   * The 1-byte serialization header is stripped from {@code getH()}.
   */
  public static final int PUBLIC_KEY_LENGTH = 896;
  /** Protocol-level upper bound on Falcon-512 signature length (variable). */
  public static final int SIGNATURE_LENGTH = 752;
  /** Falcon keygen seeds an internal SHAKE256 from 48 bytes of randomness. */
  public static final int SEED_LENGTH = 48;

  private static final FalconParameters PARAMS = FalconParameters.falcon_512;

  private final byte[] privateKey;
  private final byte[] publicKey;

  public FNDSA() {
    AsymmetricCipherKeyPair kp = generateKeyPair(new SecureRandom());
    this.privateKey = ((FalconPrivateKeyParameters) kp.getPrivate()).getEncoded();
    this.publicKey = ((FalconPublicKeyParameters) kp.getPublic()).getH();
  }

  public FNDSA(byte[] seed) {
    if (seed == null || seed.length != SEED_LENGTH) {
      throw new IllegalArgumentException("FN-DSA seed length must be " + SEED_LENGTH);
    }
    AsymmetricCipherKeyPair kp = generateKeyPair(new FixedSecureRandom(seed));
    this.privateKey = ((FalconPrivateKeyParameters) kp.getPrivate()).getEncoded();
    this.publicKey = ((FalconPublicKeyParameters) kp.getPublic()).getH();
  }

  public FNDSA(byte[] privateKey, byte[] publicKey) {
    validatePrivateKeyBytes(privateKey);
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "FN-DSA public key length must be " + PUBLIC_KEY_LENGTH);
    }
    this.privateKey = privateKey.clone();
    this.publicKey = publicKey.clone();
  }

  @Override
  public SignatureScheme getScheme() {
    return SignatureScheme.FN_DSA;
  }

  @Override
  public int getPrivateKeyLength() {
    return PRIVATE_KEY_LENGTH;
  }

  @Override
  public int getPublicKeyLength() {
    return PUBLIC_KEY_LENGTH;
  }

  /** Returns the protocol-level signature length upper bound (signatures are variable-length). */
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
          "FN-DSA public key length must be " + PUBLIC_KEY_LENGTH);
    }
    if (signature == null || signature.length == 0 || signature.length > SIGNATURE_LENGTH) {
      throw new IllegalArgumentException(
          "FN-DSA signature length must be 1.." + SIGNATURE_LENGTH);
    }
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    FalconPublicKeyParameters pk = new FalconPublicKeyParameters(PARAMS, publicKey);
    FalconSigner verifier = new FalconSigner();
    verifier.init(false, pk);
    try {
      return verifier.verifySignature(message, signature);
    } catch (RuntimeException e) {
      return false;
    }
  }

  public static byte[] sign(byte[] privateKey, byte[] message) {
    validatePrivateKeyBytes(privateKey);
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    byte[] f = new byte[F_G_ENCODED_LENGTH];
    byte[] g = new byte[F_G_ENCODED_LENGTH];
    byte[] bigF = new byte[BIG_F_ENCODED_LENGTH];
    System.arraycopy(privateKey, 0, f, 0, f.length);
    System.arraycopy(privateKey, f.length, g, 0, g.length);
    System.arraycopy(privateKey, f.length + g.length, bigF, 0, bigF.length);
    FalconPrivateKeyParameters sk = new FalconPrivateKeyParameters(PARAMS, f, g, bigF, new byte[0]);
    FalconSigner signer = new FalconSigner();
    signer.init(true, new ParametersWithRandom(sk, new SecureRandom()));
    try {
      return signer.generateSignature(message);
    } catch (Exception e) {
      throw new IllegalStateException("FN-DSA signing failed", e);
    }
  }

  public static byte[] derivePublicKey(byte[] privateKey) {
    throw new UnsupportedOperationException(
        "FN-DSA public key cannot be derived from the encoded private key alone; "
            + "supply both halves to the (privateKey, publicKey) constructor");
  }

  public static byte[] computeAddress(byte[] publicKey) {
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "FN-DSA public key length must be " + PUBLIC_KEY_LENGTH);
    }
    return Hash.sha3omit12(publicKey);
  }

  private static AsymmetricCipherKeyPair generateKeyPair(SecureRandom random) {
    FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
    generator.init(new FalconKeyGenerationParameters(random, PARAMS));
    return generator.generateKeyPair();
  }

  private static void validatePrivateKeyBytes(byte[] privateKey) {
    if (privateKey == null || privateKey.length != PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "FN-DSA private key length must be " + PRIVATE_KEY_LENGTH);
    }
  }
}
