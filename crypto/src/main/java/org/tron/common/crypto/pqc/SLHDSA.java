package org.tron.common.crypto.pqc;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.tron.common.crypto.Hash;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * FIPS 205 SLH-DSA-SHA2-128s keypair-bound signer/verifier. Mirrors the
 * {@link MLDSA44} / {@link MLDSA65} shape: instance methods sign/verify with
 * the bound keypair, static {@link #sign(byte[], byte[])} / {@link #verify}
 * provide stateless entry points used by {@link PqSignatureRegistry}.
 */
public final class SLHDSA implements PqSignature {

  public static final int PRIVATE_KEY_LENGTH = 64;
  public static final int PUBLIC_KEY_LENGTH = 32;
  public static final int SIGNATURE_LENGTH = 7856;
  /** SLH-DSA-SHA2-128s requires 3 × n = 48 bytes of randomness for keygen (n = 16). */
  public static final int SEED_LENGTH = 48;

  private static final SLHDSAParameters PARAMS = SLHDSAParameters.sha2_128s;

  private final byte[] privateKey;
  private final byte[] publicKey;

  public SLHDSA() {
    this.privateKey = generatePrivateKey();
    this.publicKey = derivePublicKey(this.privateKey);
  }

  public SLHDSA(byte[] seed) {
    if (seed == null || seed.length != SEED_LENGTH) {
      throw new IllegalArgumentException("SLH-DSA seed length must be " + SEED_LENGTH);
    }
    this.privateKey = generatePrivateKeyFromSeed(seed);
    this.publicKey = derivePublicKey(this.privateKey);
  }

  public SLHDSA(byte[] privateKey, byte[] publicKey) {
    validatePrivateKeyBytes(privateKey);
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "SLH-DSA public key length must be " + PUBLIC_KEY_LENGTH);
    }
    this.privateKey = privateKey.clone();
    this.publicKey = publicKey.clone();
  }

  public static SLHDSA fromPrivate(byte[] privateKey) {
    validatePrivateKeyBytes(privateKey);
    byte[] sk = privateKey.clone();
    return new SLHDSA(sk, derivePublicKey(sk));
  }

  @Override
  public SignatureScheme getScheme() {
    return SignatureScheme.SLH_DSA;
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
          "SLH-DSA public key length must be " + PUBLIC_KEY_LENGTH);
    }
    if (signature == null || signature.length != SIGNATURE_LENGTH) {
      throw new IllegalArgumentException(
          "SLH-DSA signature length must be " + SIGNATURE_LENGTH);
    }
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    SLHDSAPublicKeyParameters pk = new SLHDSAPublicKeyParameters(PARAMS, publicKey);
    SLHDSASigner verifier = new SLHDSASigner();
    verifier.init(false, pk);
    return verifier.verifySignature(message, signature);
  }

  public static byte[] sign(byte[] privateKey, byte[] message) {
    validatePrivateKeyBytes(privateKey);
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    SLHDSAPrivateKeyParameters sk = new SLHDSAPrivateKeyParameters(PARAMS, privateKey);
    SLHDSASigner signer = new SLHDSASigner();
    signer.init(true, sk);
    try {
      return signer.generateSignature(message);
    } catch (Exception e) {
      throw new IllegalStateException("SLH-DSA signing failed", e);
    }
  }

  public static byte[] generatePrivateKey() {
    return generatePrivateKey(new SecureRandom());
  }

  public static byte[] generatePrivateKeyFromSeed(byte[] seed) {
    if (seed == null || seed.length != SEED_LENGTH) {
      throw new IllegalArgumentException(
          "SLH-DSA seed length must be " + SEED_LENGTH);
    }
    return generatePrivateKey(new FixedSecureRandom(seed));
  }

  private static byte[] generatePrivateKey(SecureRandom random) {
    SLHDSAKeyPairGenerator generator = new SLHDSAKeyPairGenerator();
    generator.init(new SLHDSAKeyGenerationParameters(random, PARAMS));
    AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
    return ((SLHDSAPrivateKeyParameters) keyPair.getPrivate()).getEncoded();
  }

  public static byte[] derivePublicKey(byte[] privateKey) {
    validatePrivateKeyBytes(privateKey);
    SLHDSAPrivateKeyParameters sk = new SLHDSAPrivateKeyParameters(PARAMS, privateKey);
    return sk.getEncodedPublicKey();
  }

  public static byte[] computeAddress(byte[] publicKey) {
    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "SLH-DSA public key length must be " + PUBLIC_KEY_LENGTH);
    }
    return Hash.sha3omit12(publicKey);
  }

  private static void validatePrivateKeyBytes(byte[] privateKey) {
    if (privateKey == null || privateKey.length != PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "SLH-DSA private key length must be " + PRIVATE_KEY_LENGTH);
    }
  }
}
