package org.tron.common.crypto.pqc;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import lombok.Getter;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;

import java.security.*;

/**
 * Dilithium signature algorithm utility class Provides key generation, signing and verification
 * functionality
 */
public class Dilithium extends PQCBase {

  // Dilithium algorithm parameter specifications
  public static final DilithiumParameterSpec DILITHIUM2 = DilithiumParameterSpec.dilithium2;
  public static final DilithiumParameterSpec DILITHIUM3 = DilithiumParameterSpec.dilithium3;
  public static final DilithiumParameterSpec DILITHIUM5 = DilithiumParameterSpec.dilithium5;

  @Getter
  private DilithiumParameterSpec parameterSpec;

  /**
   * Constructor, using default Dilithium2 parameter specification
   */
  public Dilithium() {
    this(DILITHIUM2);
  }

  /**
   * Constructor, specifying parameter specification
   *
   * @param parameterSpec parameter specification (Dilithium2/3/5)
   */
  public Dilithium(DilithiumParameterSpec parameterSpec) {
    if (parameterSpec == null) {
      throw new IllegalArgumentException("Dilithium parameter specification cannot be null.");
    }
    this.parameterSpec = parameterSpec;

    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
      kpg.initialize(parameterSpec);
      KeyPair keyPair = kpg.generateKeyPair();
      this.privateKey = keyPair.getPrivate();
      this.publicKey = keyPair.getPublic();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (NoSuchProviderException e) {
      throw new RuntimeException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Constructs a Dilithium key pair from provided private and public key bytes.
   * <p>
   * Note:
   * <ul>
   *   <li>Dilithium public keys CANNOT be derived from private keys — both keys must be provided
   *   * .</li>
   *   <li>Private key must be encoded in PKCS#8 format.</li>
   *   <li>Public key must be encoded in X.509 SubjectPublicKeyInfo format.</li>
   *   <li>Supported parameter specifications: Dilithium2, Dilithium3, Dilithium5.</li>
   *   <li>Provider used: BouncyCastle PQC ("BCPQC").</li>
   * </ul>
   * </p>
   *
   * @param privateKeyBytes the private key in PKCS#8 byte encoding
   * @param publicKeyBytes  the public key in X.509 byte encoding
   * @throws IllegalArgumentException if parameter specification is invalid or byte arrays are
   *                                  invalid
   * @throws GeneralSecurityException if key reconstruction fails due to format/provider issues
   */
  public Dilithium(byte[] privateKeyBytes, byte[] publicKeyBytes)
      throws GeneralSecurityException {
    if (ByteArray.isEmpty(privateKeyBytes) || ByteArray.isEmpty(publicKeyBytes)) {
      throw new IllegalArgumentException(
          "Dilithium private or public key bytes cannot be null or empty.");
    }

    // Use Dilithium KeyFactory from BouncyCastle PQC provider
    KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");

    // Reconstruct private key (PKCS#8)
    PrivateKey privateKey = keyFactory.generatePrivate(
        new PKCS8EncodedKeySpec(privateKeyBytes)
    );
    if (!(privateKey instanceof BCDilithiumPrivateKey)) {
      throw new InvalidKeyException("Invalid Dilithium private key.");
    }

    // Reconstruct public key (X.509)
    PublicKey publicKey = keyFactory.generatePublic(
        new X509EncodedKeySpec(publicKeyBytes)
    );
    if (!(publicKey instanceof BCDilithiumPublicKey)) {
      throw new InvalidKeyException("Invalid Dilithium public key.");
    }

    // Validate key pair correctness
    if (!validateKeyPair(privateKey, publicKey)) {
      throw new InvalidKeyException("Dilithium private/public key pair mismatch.");
    }

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Set externally provided key pair
   *
   * @param keyPair       key pair
   * @return current instance
   */
  public Dilithium(KeyPair keyPair)
      throws GeneralSecurityException {
    if (keyPair == null) {
      throw new IllegalArgumentException("Dilithium KeyPair cannot be null.");
    }
    PrivateKey privateKey = keyPair.getPrivate();
    if (!(privateKey instanceof BCDilithiumPrivateKey)) {
      throw new InvalidKeyException("Invalid Dilithium private key.");
    }
    PublicKey publicKey = keyPair.getPublic();
    if (!(publicKey instanceof BCDilithiumPublicKey)) {
      throw new InvalidKeyException("Invalid Dilithium public key.");
    }

    // Validate key pair correctness
    if (!validateKeyPair(privateKey, publicKey)) {
      throw new InvalidKeyException("Dilithium private/public key pair mismatch.");
    }

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Validate a Dilithium key pair by signing and verifying a test message. This is the only
   * reliable way because Dilithium public keys cannot be derived from private keys.
   */
  private static boolean validateKeyPair(PrivateKey priv, PublicKey pub)
      throws GeneralSecurityException {
    Signature sig = Signature.getInstance("Dilithium", "BCPQC");

    byte[] hash = Sha256Hash.hash(true, "Verify Dilithium signature key pair".getBytes());

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
   * Sign message using current private key
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

    Signature signer = Signature.getInstance("Dilithium", "BCPQC");
    signer.initSign(getPrivateKey());

    signer.update(message);
    return signer.sign();
  }

  /**
   * Sign message using specified private key
   *
   * @param privateKey    private key
   * @param message       message to sign
   * @return signature byte array
   * @throws GeneralSecurityException
   */
  public static byte[] sign(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {

    Signature signer = Signature.getInstance("Dilithium", "BCPQC");
    signer.initSign(privateKey);

    signer.update(message);
    return signer.sign();
  }

  /**
   * Verify signature using current public key
   *
   * @param message   original message
   * @param signature signature
   * @return verification result
   * @throws GeneralSecurityException
   */
  public boolean verify(byte[] message, byte[] signature) throws GeneralSecurityException {
    if (getPublicKey() == null) {
      throw new IllegalStateException(
          "Public key not available. Generate or set a key pair first.");
    }

    return verify(getPublicKey(), message, signature);
  }

  /**
   * Verify signature using specified public key
   *
   * @param publicKey     public key
   * @param message       original message
   * @param signature     signature
   * @return verification result
   * @throws GeneralSecurityException
   */
  public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature)
      throws GeneralSecurityException {
    Signature verifier = Signature.getInstance("Dilithium", "BCPQC");
    verifier.initVerify(publicKey);

    verifier.update(message);
    return verifier.verify(signature);
  }
}
