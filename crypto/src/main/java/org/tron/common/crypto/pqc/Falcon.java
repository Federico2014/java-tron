package org.tron.common.crypto.pqc;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import lombok.Getter;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPublicKey;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;

import java.security.*;

/**
 * Falcon signature algorithm utility class
 * Provides key generation, signing and verification functionality
 */
public class Falcon extends PQCBase {

  // Falcon algorithm constants
  public static final String FALCON_512 = "Falcon-512";
  public static final String FALCON_1024 = "Falcon-1024";

  @Getter
  private final String algorithm;

  /**
   * Constructor, using default Falcon-512 algorithm
   */
  public Falcon() {
    this(FALCON_512);
  }

  /**
   * Constructor, specifying algorithm type and generate a new key pair
   * @param algorithm algorithm name ("Falcon-512" or "Falcon-1024")
   */
  public Falcon(String algorithm) {
    this.algorithm = algorithm;
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "BCPQC");
      KeyPair keyPair = kpg.generateKeyPair();
      this.privateKey = keyPair.getPrivate();
      this.publicKey = keyPair.getPublic();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Constructor, using private key bytes with default Falcon-512 algorithm
   * @param privateKeyBytes private key as byte array
   * @throws GeneralSecurityException
   */
  public Falcon(byte[] privateKeyBytes, byte[] publicKeyBytes) throws GeneralSecurityException {
    this(privateKeyBytes, publicKeyBytes, FALCON_512);
  }

  /**
   * Constructs a Falcon key pair from provided private and public key bytes.
   * <p>
   * Note:
   * <ul>
   *   <li>Falcon public keys CANNOT be derived from private keys — both keys must be provided.</li>
   *   <li>Private key must be encoded in PKCS#8 format.</li>
   *   <li>Public key must be encoded in X.509 SubjectPublicKeyInfo format.</li>
   *   <li>Supported algorithm values: "Falcon-512", "Falcon-1024".</li>
   *   <li>Provider used: BouncyCastle PQC ("BCPQC").</li>
   * </ul>
   * </p>
   *
   * @param privateKeyBytes  the private key in PKCS#8 byte encoding
   * @param publicKeyBytes   the public key in X.509 byte encoding
   * @param algorithm        must be "Falcon-512" or "Falcon-1024"
   *
   * @throws IllegalArgumentException   if algorithm is unsupported or byte arrays are invalid
   * @throws GeneralSecurityException   if key reconstruction fails due to format/provider issues
   */
  public Falcon(byte[] privateKeyBytes, byte[] publicKeyBytes, String algorithm)
      throws GeneralSecurityException {
    checkFalconAlgorithm(algorithm);
    this.algorithm = algorithm;

    if (ByteArray.isEmpty(privateKeyBytes) || ByteArray.isEmpty(publicKeyBytes)) {
      throw new IllegalArgumentException(
          "Falcon private or public key bytes cannot be null or empty.");
    }

    // Use Falcon KeyFactory from BouncyCastle PQC provider
    KeyFactory keyFactory = KeyFactory.getInstance("Falcon", "BCPQC");

    // Reconstruct private key (PKCS#8)
    PrivateKey privateKey = keyFactory.generatePrivate(
        new PKCS8EncodedKeySpec(privateKeyBytes)
    );
    if (!(privateKey instanceof BCFalconPrivateKey)) {
      throw new InvalidKeyException("Invalid Falcon private key.");
    }

    // Reconstruct public key (X.509)
    PublicKey publicKey = keyFactory.generatePublic(
        new X509EncodedKeySpec(publicKeyBytes)
    );
    if (!(publicKey instanceof BCFalconPublicKey)) {
      throw new InvalidKeyException("Invalid Falcon public key.");
    }

    // Validate key pair correctness
    if (!validateKeyPair(privateKey, publicKey, algorithm)) {
      throw new InvalidKeyException("Falcon private/public key pair mismatch.");
    }

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Set externally provided key pair
   * @param keyPair key pair
   * @return current instance, supports method chaining
   */
  public Falcon(KeyPair keyPair, String algorithm) throws GeneralSecurityException {
    if (keyPair == null) {
      throw new IllegalArgumentException("KeyPair cannot be null.");
    }
    PrivateKey privateKey = keyPair.getPrivate();
    if (!(privateKey instanceof BCFalconPrivateKey)) {
      throw new InvalidKeyException("Invalid Falcon private key.");
    }
    PublicKey publicKey = keyPair.getPublic();
    if (!(publicKey instanceof BCFalconPublicKey)) {
      throw new InvalidKeyException("Invalid Falcon public key.");
    }

    // Validate key pair correctness
    if (!validateKeyPair(privateKey, publicKey, algorithm)) {
      throw new InvalidKeyException("Falcon private/public key pair mismatch.");
    }

    this.algorithm = algorithm;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  private static void checkFalconAlgorithm(String algorithm) {
    if (!algorithm.equals(FALCON_512) && !algorithm.equals(FALCON_1024)) {
      throw new IllegalArgumentException("Invalid Falcon signature algorithm: " + algorithm);
    }
  }

  /**
   * Validate a Falcon key pair by signing and verifying a test message.
   * This is the only reliable way because Falcon public keys cannot be derived from private keys.
   */
  private static boolean validateKeyPair(PrivateKey priv, PublicKey pub, String algorithm)
      throws GeneralSecurityException {
    checkFalconAlgorithm(algorithm);
    Signature sig = Signature.getInstance(algorithm, "BCPQC");

    byte[] hash = Sha256Hash.hash(true, "Verify Falcon signature key pair".getBytes());

    try {
      sig.initSign(priv);
      sig.update(hash);
      byte[] s = sig.sign();

      sig.initVerify(pub);
      sig.update(hash);
      return sig.verify(s);
    } catch (SignatureException e) {
      return false;
    }
  }

  /**
   * Sign message hash using current private key
   *
   * @param message message to sign
   * @return signature byte array
   * @throws GeneralSecurityException
   */
  public byte[] sign(byte[] message) throws GeneralSecurityException {
    if (getPrivateKey() == null) {
      throw new IllegalStateException(
          "Private key not available. Generate or set a key pair first.");
    }

    Signature signer = Signature.getInstance(algorithm, "BCPQC");
    signer.initSign(getPrivateKey());

    signer.update(message);
    return signer.sign();
  }

  /**
   * Sign message using specified private key
   * @param privateKey private key
   * @param message message to sign
   * @return signature byte array
   * @throws GeneralSecurityException
   */
  public static byte[] sign(PrivateKey privateKey, byte[] message, String algorithm)
      throws GeneralSecurityException {
    checkFalconAlgorithm(algorithm);
    Signature signer = Signature.getInstance(algorithm, "BCPQC");
    signer.initSign(privateKey);

    signer.update(message);
    return signer.sign();
  }

  /**
   * Sign message using specified private key with default algorithm
   * @param privateKey private key
   * @param message message to sign
   * @return signature byte array
   * @throws GeneralSecurityException
   */
  public static byte[] sign(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {
    return sign(privateKey, message, FALCON_512);
  }

  /**
   * Verify signature using current public key
   * @param hash original message hash
   * @param signature signature
   * @return verification result
   * @throws GeneralSecurityException
   */
  public boolean verify(byte[] hash, byte[] signature) throws GeneralSecurityException {
    if (getPublicKey() == null) {
      throw new IllegalStateException("Public key not available. Generate or set a key pair first.");
    }

    return verify(getPublicKey(), hash, signature, algorithm);
  }

  /**
   * Verify signature using specified public key
   * @param publicKey public key
   * @param message original message
   * @param signature signature
   * @param algorithm algorithm name
   * @return verification result
   * @throws GeneralSecurityException
   */
  public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature, String algorithm)
      throws GeneralSecurityException {
    Signature verifier = Signature.getInstance(algorithm, "BCPQC");
    verifier.initVerify(publicKey);

    verifier.update(message);
    return verifier.verify(signature);
  }

  /**
   * Verify signature using specified public key with default algorithm
   * @param publicKey public key
   * @param message original message
   * @param signature signature
   * @return verification result
   * @throws GeneralSecurityException
   */
  public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature)
      throws GeneralSecurityException {
    return verify(publicKey, message, signature, FALCON_512);
  }
}

