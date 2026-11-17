package org.tron.keystore;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.utils.Base58;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.DecodeUtil;
import org.tron.common.utils.StringUtil;
import org.tron.core.exception.CipherException;

/**
 * <p>Ethereum wallet file management. For reference, refer to <a href="https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition">
 * Web3 Secret Storage Definition</a> or the <a href="https://github.com/ethereum/go-ethereum/blob/master/accounts/key_store_passphrase.go">
 * Go Ethereum client implementation</a>.</p>
 *
 * <p>Scrypt parameters are checked against RFC 7914 and the supported resource limits
 * before invoking {@link SCrypt}.</p>
 */
public class Wallet {

  // KDF identifiers used in the Web3 Secret Storage "kdf" field.
  // The old name "AES_128_CTR" was misleading — the value is the PBKDF2 KDF
  // identifier, not the cipher (CIPHER below). The inner class name
  // `WalletFile.Aes128CtrKdfParams` is kept for wire-format/Jackson-subtype
  // backward compatibility even though it also reflects the same history.
  protected static final String PBKDF2 = "pbkdf2";
  protected static final String SCRYPT = "scrypt";
  private static final int N_LIGHT = 1 << 12;
  private static final int P_LIGHT = 6;
  private static final int N_STANDARD = 1 << 18;
  private static final int P_STANDARD = 1;
  private static final int R = 8;
  private static final int DKLEN = 32;
  private static final int CURRENT_VERSION = 3;
  private static final String CIPHER = "aes-128-ctr";

  // Upper bounds for untrusted keystore KDF cost parameters. A hostile
  // keystore file may declare arbitrary KDF strengths: extreme scrypt
  // parameters make Bouncy Castle either allocate unbounded memory
  // (n*r*128 bytes — e.g. n=2^22, r=8 requests 4 GiB and dies with OOM)
  // or compute for hours, and out-of-range values can crash the JVM with
  // NegativeArraySizeException / ArithmeticException inside SCrypt.generate.
  // All values here are rejected by validationError() before any KDF runs.
  private static final int SCRYPT_N_MIN = 1 << 12;
  private static final int SCRYPT_N_MAX = 1 << 20;
  private static final int SCRYPT_R_MAX = 8;
  private static final int SCRYPT_P_MAX = 8;
  private static final long SCRYPT_MEMORY_MAX_BYTES = 1L << 30; // 128 * r * n cap = 1 GiB
  private static final int KDF_DKLEN_MAX = 128;
  private static final int KDF_SALT_MAX_BYTES = 1024;
  private static final int PBKDF2_C_MAX = 1 << 20;

  /**
   * Creates a keystore. The caller must ensure the signing key's address matches its private key.
   */
  public static WalletFile create(String password, SignInterface sign, int n, int p)
      throws CipherException {

    if (!WalletUtils.passwordValid(password)) {
      throw new CipherException("Password must be at least 6 characters");
    }
    if (sign == null) {
      throw new CipherException("Missing signing key");
    }

    // Keep create() symmetric with validate()/decrypt(): reject KDF cost
    // parameters that the decryption path would refuse, so create() can
    // never produce a wallet file that only this class rejects.
    String paramError = scryptKdfParamsError(DKLEN, n, R, p);
    if (paramError != null) {
      throw new CipherException(paramError);
    }

    byte[] privateKeyBytes = sign.getPrivateKey();
    if (!ECKey.isValidPrivateKey(privateKeyBytes)) {
      throw new CipherException("Invalid private key");
    }

    byte[] salt = generateRandomBytes(32);

    byte[] derivedKey;
    try {
      derivedKey = generateDerivedScryptKey(password.getBytes(UTF_8), salt, n, R, p, DKLEN);
    } catch (RuntimeException e) {
      throw new CipherException("Scrypt key derivation failed", e);
    }

    byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
    byte[] iv = generateRandomBytes(16);

    byte[] cipherText = performCipherOperation(Cipher.ENCRYPT_MODE, iv, encryptKey,
        privateKeyBytes);

    byte[] mac = generateMac(derivedKey, cipherText);

    return createWalletFile(sign, cipherText, iv, salt, mac, n, p);
  }

  public static WalletFile createStandard(String password, SignInterface cryptoEngine)
      throws CipherException {
    return create(password, cryptoEngine, N_STANDARD, P_STANDARD);
  }

  public static WalletFile createLight(String password, SignInterface cryptoEngine)
      throws CipherException {
    return create(password, cryptoEngine, N_LIGHT, P_LIGHT);
  }

  private static WalletFile createWalletFile(
      SignInterface ecKeyPair, byte[] cipherText, byte[] iv, byte[] salt, byte[] mac,
      int n, int p) {

    WalletFile walletFile = new WalletFile();
    walletFile.setAddress(StringUtil.encode58Check(ecKeyPair.getAddress()));

    WalletFile.Crypto crypto = new WalletFile.Crypto();
    crypto.setCipher(CIPHER);
    crypto.setCiphertext(ByteArray.toHexString(cipherText));
    walletFile.setCrypto(crypto);

    WalletFile.CipherParams cipherParams = new WalletFile.CipherParams();
    cipherParams.setIv(ByteArray.toHexString(iv));
    crypto.setCipherparams(cipherParams);

    crypto.setKdf(SCRYPT);
    WalletFile.ScryptKdfParams kdfParams = new WalletFile.ScryptKdfParams();
    kdfParams.setDklen(DKLEN);
    kdfParams.setN(n);
    kdfParams.setP(p);
    kdfParams.setR(R);
    kdfParams.setSalt(ByteArray.toHexString(salt));
    crypto.setKdfparams(kdfParams);

    crypto.setMac(ByteArray.toHexString(mac));
    walletFile.setCrypto(crypto);
    walletFile.setId(UUID.randomUUID().toString());
    walletFile.setVersion(CURRENT_VERSION);

    return walletFile;
  }

  private static byte[] generateDerivedScryptKey(
      byte[] password, byte[] salt, int n, int r, int p, int dkLen) throws CipherException {
    return SCrypt.generate(password, salt, n, r, p, dkLen);
  }

  private static byte[] generateAes128CtrDerivedKey(
      byte[] password, byte[] salt, int c, String prf, int dklen) throws CipherException {

    if (!"hmac-sha256".equals(prf)) {
      throw new CipherException("Unsupported prf:" + prf);
    }

    // Java 8 supports this, but you have to convert the password to a character array, see
    // http://stackoverflow.com/a/27928435/3211687

    PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
    gen.init(password, salt, c);
    return ((KeyParameter) gen.generateDerivedParameters(dklen * 8)).getKey();
  }

  private static byte[] performCipherOperation(
      int mode, byte[] iv, byte[] encryptKey, byte[] text) throws CipherException {

    try {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

      SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
      cipher.init(mode, secretKeySpec, ivParameterSpec);
      return cipher.doFinal(text);
    } catch (NoSuchPaddingException | NoSuchAlgorithmException
        | InvalidAlgorithmParameterException | InvalidKeyException
        | BadPaddingException | IllegalBlockSizeException e) {
      throw new CipherException("Error performing cipher operation", e);
    }
  }

  private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
    byte[] result = new byte[16 + cipherText.length];

    System.arraycopy(derivedKey, 16, result, 0, 16);
    System.arraycopy(cipherText, 0, result, 16, cipherText.length);

    return Hash.sha3(result);
  }

  public static SignInterface decrypt(String password, WalletFile walletFile)
      throws CipherException {

    validate(walletFile);

    WalletFile.Crypto crypto = walletFile.getCrypto();

    byte[] mac = ByteArray.fromHexString(crypto.getMac());
    byte[] iv = ByteArray.fromHexString(crypto.getCipherparams().getIv());
    byte[] cipherText = ByteArray.fromHexString(crypto.getCiphertext());

    byte[] derivedKey;

    WalletFile.KdfParams kdfParams = crypto.getKdfparams();
    if (kdfParams instanceof WalletFile.ScryptKdfParams) {
      WalletFile.ScryptKdfParams scryptKdfParams =
          (WalletFile.ScryptKdfParams) crypto.getKdfparams();
      int dklen = scryptKdfParams.getDklen();
      int n = scryptKdfParams.getN();
      int p = scryptKdfParams.getP();
      int r = scryptKdfParams.getR();
      byte[] salt = ByteArray.fromHexString(scryptKdfParams.getSalt());
      try {
        derivedKey = generateDerivedScryptKey(password.getBytes(UTF_8), salt, n, r, p, dklen);
      } catch (RuntimeException e) {
        // Defense-in-depth: any residual KDF engine failure (e.g. an
        // IllegalArgumentException from Bouncy Castle) must surface as a
        // clean CipherException, never as a raw RuntimeException stack.
        // Errors (OutOfMemoryError etc.) are deliberately not caught —
        // they remain fatal.
        throw new CipherException("Scrypt key derivation failed", e);
      }
    } else if (kdfParams instanceof WalletFile.Aes128CtrKdfParams) {
      WalletFile.Aes128CtrKdfParams aes128CtrKdfParams =
          (WalletFile.Aes128CtrKdfParams) crypto.getKdfparams();
      int c = aes128CtrKdfParams.getC();
      String prf = aes128CtrKdfParams.getPrf();
      byte[] salt = ByteArray.fromHexString(aes128CtrKdfParams.getSalt());

      try {
        derivedKey = generateAes128CtrDerivedKey(password.getBytes(UTF_8), salt, c, prf,
            aes128CtrKdfParams.getDklen());
      } catch (RuntimeException e) {
        throw new CipherException("Pbkdf2 key derivation failed", e);
      }
    } else {
      throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
    }

    byte[] encryptKey = null;
    byte[] privateKey = null;
    try {
      byte[] derivedMac = generateMac(derivedKey, cipherText);

      if (!java.security.MessageDigest.isEqual(derivedMac, mac)) {
        throw new CipherException("Invalid password provided");
      }

      encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
      privateKey = performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);

      SignInterface keyPair;
      try {
        keyPair = SignUtils.fromPrivate(privateKey);
      } catch (IllegalArgumentException e) {
        throw new CipherException("Invalid private key in keystore", e);
      }

      // Enforce address consistency: if the keystore declares an address, it MUST match
      // the address derived from the decrypted private key. Prevents address spoofing
      // where a crafted keystore displays one address but encrypts a different key.
      String declared = walletFile.getAddress();
      if (declared != null && !declared.isEmpty()) {
        String derived = StringUtil.encode58Check(keyPair.getAddress());
        if (!declared.equals(derived)) {
          throw new CipherException(
              "Keystore address mismatch: file declares " + declared
                  + " but private key derives " + derived);
        }
      }

      return keyPair;
    } finally {
      Arrays.fill(derivedKey, (byte) 0);
      if (encryptKey != null) {
        Arrays.fill(encryptKey, (byte) 0);
      }
      if (privateKey != null) {
        Arrays.fill(privateKey, (byte) 0);
      }
    }
  }

  /**
   * Returns a description of the first schema violation found in
   * {@code walletFile}, or {@code null} if the file matches the supported
   * V3 keystore shape, including required fields, encodings, lengths, and KDF
   * parameters within supported bounds. This does not verify the password or MAC.
   *
   * <p>KDF cost bounds are enforced here — the single chokepoint shared by
   * {@link #validate(WalletFile)} (which throws the message) and
   * {@link #isValidKeystoreFile(WalletFile)} (which returns boolean for
   * discovery-style filtering) — so untrusted keystore files can never
   * drive the KDF into unbounded memory allocation, multi-hour CPU
   * exhaustion, or engine-level crashes before {@link #decrypt} runs.
   */
  private static String validationError(WalletFile walletFile) {
    if (walletFile == null) {
      return "Missing wallet file";
    }
    if (walletFile.getVersion() != CURRENT_VERSION) {
      return "Wallet version is not supported";
    }
    String address = walletFile.getAddress();
    // An absent address remains supported for imported keystores.
    if (address != null && !address.isEmpty() && !validAddress(address)) {
      return "Invalid keystore address";
    }
    WalletFile.Crypto crypto = walletFile.getCrypto();
    if (crypto == null) {
      return "Missing crypto section";
    }
    String cipher = crypto.getCipher();
    if (cipher == null || !cipher.equals(CIPHER)) {
      return "Wallet cipher is not supported";
    }
    if (crypto.getCipherparams() == null) {
      return "Missing cipherparams";
    }
    String iv = crypto.getCipherparams().getIv();
    if (iv == null || iv.length() > 34 || !StringUtil.isHexadecimal(iv)
        || ByteArray.fromHexString(iv).length != 16) {
      return "IV must be 16 bytes of hex";
    }
    String ciphertext = crypto.getCiphertext();
    // Allow the private-key encodings accepted by ECKey; validate the scalar after decryption.
    if (ciphertext == null
        || ciphertext.length() > 68
        || !StringUtil.isHexadecimal(ciphertext)
        || ByteArray.fromHexString(ciphertext).length > 33) {
      return "Ciphertext must be 1 to 33 bytes of hex";
    }
    String mac = crypto.getMac();
    if (mac == null || mac.length() > 66 || !StringUtil.isHexadecimal(mac)
        || ByteArray.fromHexString(mac).length != 32) {
      return "MAC must be 32 bytes of hex";
    }
    String kdf = crypto.getKdf();
    if (kdf == null || (!kdf.equals(PBKDF2) && !kdf.equals(SCRYPT))) {
      return "KDF type is not supported";
    }
    WalletFile.KdfParams kdfParams = crypto.getKdfparams();
    if (kdfParams == null) {
      return "Missing kdfparams";
    }
    String salt = kdfParams.getSalt();
    if (salt != null
        && salt.length() > 2 * KDF_SALT_MAX_BYTES + (salt.startsWith("0x") ? 2 : 0)) {
      return "KDF salt exceeds " + KDF_SALT_MAX_BYTES + " bytes";
    }
    if (SCRYPT.equals(kdf)) {
      if (!(kdfParams instanceof WalletFile.ScryptKdfParams)) {
        return "Scrypt KDF params are missing or malformed";
      }
      WalletFile.ScryptKdfParams params = (WalletFile.ScryptKdfParams) kdfParams;
      if (!StringUtil.isHexadecimal(params.getSalt())) {
        return "Scrypt salt must be non-empty hex";
      }
      return scryptKdfParamsError(params.getDklen(), params.getN(), params.getR(), params.getP());
    }
    if (!(kdfParams instanceof WalletFile.Aes128CtrKdfParams)) {
      return "Pbkdf2 KDF params are missing or malformed";
    }
    WalletFile.Aes128CtrKdfParams params = (WalletFile.Aes128CtrKdfParams) kdfParams;
    if (!StringUtil.isHexadecimal(params.getSalt())) {
      return "Pbkdf2 salt must be non-empty hex";
    }
    if (!"hmac-sha256".equals(params.getPrf())) {
      return "Unsupported prf: " + params.getPrf();
    }
    return pbkdf2KdfParamsError(params.getDklen(), params.getC());
  }

  private static boolean validAddress(String address) {
    // Bound Base58 decoding before allocating or doing quadratic conversion work.
    if (address.length() > 34) {
      return false;
    }
    try {
      byte[] decoded = Base58.decode(address);
      if (decoded.length != 25) {
        return false;
      }
      byte[] payload = Arrays.copyOf(decoded, 21);
      return DecodeUtil.addressValid(payload) && StringUtil.encode58Check(payload).equals(address);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private static String scryptKdfParamsError(int dklen, int n, int r, int p) {
    // dklen must yield at least 32 bytes: generateMac copies derivedKey[16..32)
    // and AES-128 needs bytes [0..16); smaller keys throw raw ArrayIndexOutOfBoundsException.
    if (dklen < 32 || dklen > KDF_DKLEN_MAX) {
      return "Scrypt dklen is out of range [32, " + KDF_DKLEN_MAX + "]: " + dklen;
    }
    if (n < SCRYPT_N_MIN || n > SCRYPT_N_MAX || (n & (n - 1)) != 0) {
      return "Scrypt n must be a power of 2 in [" + SCRYPT_N_MIN + ", " + SCRYPT_N_MAX
          + "]: " + n;
    }
    if (r < 1 || r > SCRYPT_R_MAX) {
      return "Scrypt r is out of range [1, " + SCRYPT_R_MAX + "]: " + r;
    }
    // RFC 7914 requires n < 2^(16*r); for r >= 2 the n cap already ensures this.
    if (r == 1 && n >= (1 << 16)) {
      return "Scrypt n must be less than 65536 when r is 1";
    }
    if (p < 1 || p > SCRYPT_P_MAX) {
      return "Scrypt p is out of range [1, " + SCRYPT_P_MAX + "]: " + p;
    }
    // Compute in long arithmetic: hostile r * n must not overflow int.
    long memoryBytes = 128L * r * n;
    if (memoryBytes > SCRYPT_MEMORY_MAX_BYTES) {
      return "Scrypt memory requirement 128*r*n=" + memoryBytes
          + " exceeds the " + SCRYPT_MEMORY_MAX_BYTES + " byte limit";
    }
    return null;
  }

  private static String pbkdf2KdfParamsError(int dklen, int c) {
    if (dklen < 32 || dklen > KDF_DKLEN_MAX) {
      return "Pbkdf2 dklen is out of range [32, " + KDF_DKLEN_MAX + "]: " + dklen;
    }
    if (c < 1 || c > PBKDF2_C_MAX) {
      return "Pbkdf2 iteration count c is out of range [1, " + PBKDF2_C_MAX + "]: " + c;
    }
    return null;
  }

  static void validate(WalletFile walletFile) throws CipherException {
    String error = validationError(walletFile);
    if (error != null) {
      throw new CipherException(error);
    }
  }

  /**
   * Returns {@code true} iff {@code walletFile} has a non-empty address and passes
   * the same structural checks as {@link #validate}. Intended for discovery-style
   * filtering (e.g. listing or duplicate detection). Password correctness, MAC
   * authenticity and address/private-key consistency are checked only by decrypt.
   */
  public static boolean isValidKeystoreFile(WalletFile walletFile) {
    return walletFile != null
        && walletFile.getAddress() != null
        && !walletFile.getAddress().isEmpty()
        && validationError(walletFile) == null;
  }

  public static byte[] generateRandomBytes(int size) {
    byte[] bytes = new byte[size];
    new SecureRandom().nextBytes(bytes);
    return bytes;
  }
}
