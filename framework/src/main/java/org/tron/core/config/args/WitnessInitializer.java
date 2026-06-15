package org.tron.core.config.args;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Commons;
import org.tron.common.utils.LocalWitnesses;
import org.tron.core.config.args.LocalWitnessPqConfig.PqEntryConfig;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.TronError;
import org.tron.keystore.Credentials;
import org.tron.keystore.WalletUtils;
import org.tron.protos.Protocol.PQScheme;

@Slf4j
public class WitnessInitializer {

  private static final String PQ_KEYS_PATH = LocalWitnessConfig.PQ_KEYS_PATH;

  /**
   * Init from a single private key (and optional witness address).
   */
  public static LocalWitnesses initFromCLIPrivateKey(
      String privateKey, String witnessAddress) {
    LocalWitnesses witnesses = new LocalWitnesses(privateKey);

    byte[] address = null;
    if (StringUtils.isNotEmpty(witnessAddress)) {
      address = Commons.decodeFromBase58Check(witnessAddress);
      if (address == null) {
        throw new TronError(
            "LocalWitnessAccountAddress format from cmd is incorrect",
            TronError.ErrCode.WITNESS_INIT);
      }
      logger.debug("Got localWitnessAccountAddress from cmd");
    }

    witnesses.initWitnessAccountAddress(
        address, Args.getInstance().isECKeyCryptoEngine());
    logger.debug("Got privateKey from cmd");
    return witnesses;
  }

  /**
   * Init from a list of private keys.
   */
  public static LocalWitnesses initFromCFGPrivateKey(
      List<String> privateKeys, String witnessAccountAddress) {
    LocalWitnesses witnesses = new LocalWitnesses();
    witnesses.setPrivateKeys(privateKeys);
    logger.debug("Got privateKey from config.conf");

    byte[] address = resolveWitnessAddress(witnesses, witnessAccountAddress);
    witnesses.initWitnessAccountAddress(
        address, Args.getInstance().isECKeyCryptoEngine());
    return witnesses;
  }

  /**
   * Init from keystore files with password.
   */
  public static LocalWitnesses initFromKeystore(
      List<String> keystoreFiles, String password,
      String witnessAccountAddress) {
    if (keystoreFiles.size() > 1) {
      logger.warn("Multiple keystores detected. Only the first keystore will be used"
          + " as witness, all others will be ignored.");
    }

    String fileName = System.getProperty("user.dir") + "/" + keystoreFiles.get(0);
    String pwd;
    if (StringUtils.isEmpty(password)) {
      System.out.println("Please input your password.");
      pwd = WalletUtils.inputPassword();
    } else {
      pwd = password;
    }

    List<String> privateKeys = new ArrayList<>();
    try {
      Credentials credentials = WalletUtils.loadCredentials(pwd, new File(fileName),
          Args.getInstance().isECKeyCryptoEngine());
      SignInterface sign = credentials.getSignInterface();
      String prikey = ByteArray.toHexString(sign.getPrivateKey());
      privateKeys.add(prikey);
    } catch (IOException | CipherException e) {
      logger.error("Witness node start failed!");
      // Legacy-truncation hint: if this keystore was created with
      // `FullNode.jar --keystore-factory` in non-TTY mode (e.g.
      // `echo PASS | java ...`), the legacy code encrypted with only
      // the first whitespace-separated word of the password. Emit the
      // tip only when the entered password has internal whitespace —
      // otherwise truncation cannot be the cause.
      if (e instanceof CipherException && pwd != null && pwd.matches(".*\\s.*")) {
        logger.error(
            "Tip: keystores created via `FullNode.jar --keystore-factory` in "
                + "non-TTY mode were encrypted with only the first "
                + "whitespace-separated word of the password. Try restarting "
                + "with only that first word as `-p`, then reset the password "
                + "via `java -jar Toolkit.jar keystore update`.");
      }
      throw new TronError(e, TronError.ErrCode.WITNESS_KEYSTORE_LOAD);
    }

    LocalWitnesses witnesses = new LocalWitnesses();
    witnesses.setPrivateKeys(privateKeys);
    byte[] address = resolveWitnessAddress(witnesses, witnessAccountAddress);
    witnesses.initWitnessAccountAddress(
        address, Args.getInstance().isECKeyCryptoEngine());
    logger.debug("Got privateKey from keystore");
    return witnesses;
  }

  /**
   * Init for PQ-only witness nodes (no legacy ECDSA key). Each PqKeypair carries its own PQScheme.
   * When {@code pqWitnessAccountAddress} is blank, the address is derived from the first PQ public
   * key via {@link PQSchemeRegistry#computeAddress(PQScheme, byte[])} using that entry's scheme.
   * Only {@code pqWitnessAccountAddress} is populated; the legacy ECDSA-side field stays
   * {@code null} so downstream callers must decide which identity (ECDSA vs PQ) to consult.
   */
  public static LocalWitnesses initFromPQOnly(
      List<PqKeypair> pqKeypairs, String pqWitnessAccountAddress) {
    if (pqKeypairs == null || pqKeypairs.isEmpty()) {
      throw new TronError(
          "PQ keypairs must be set for PQ-only witness nodes",
          TronError.ErrCode.WITNESS_INIT);
    }
    LocalWitnesses witnesses = new LocalWitnesses();
    witnesses.setPqKeypairs(pqKeypairs);

    byte[] accountAddress = null;
    if (StringUtils.isNotBlank(pqWitnessAccountAddress)) {
      if (pqKeypairs.size() != 1) {
        throw new TronError(
            "localwitness_pq.accountAddress can only be set when there is only one PQ keypair",
            TronError.ErrCode.WITNESS_INIT);
      }
      accountAddress = Commons.decodeFromBase58Check(pqWitnessAccountAddress);
      if (accountAddress == null) {
        throw new TronError("localwitness_pq.accountAddress format is incorrect",
            TronError.ErrCode.WITNESS_INIT);
      }
      logger.debug("Got localwitness_pq.accountAddress from config.conf");
    } else {
      logger.debug("Derived PQ-only witness address from public key");
    }
    witnesses.initPqWitnessAccountAddress(accountAddress);
    return witnesses;
  }

  static byte[] resolveWitnessAddress(
      LocalWitnesses witnesses, String witnessAccountAddress) {
    if (StringUtils.isEmpty(witnessAccountAddress)) {
      return null;
    }

    if (witnesses.getPrivateKeys().size() != 1) {
      throw new TronError(
          "LocalWitnessAccountAddress can only be set when there is only one private key",
          TronError.ErrCode.WITNESS_INIT);
    }
    byte[] address = Commons.decodeFromBase58Check(witnessAccountAddress);
    if (address != null) {
      logger.debug("Got localWitnessAccountAddress from config.conf");
    } else {
      throw new TronError("LocalWitnessAccountAddress format from config is incorrect",
          TronError.ErrCode.WITNESS_INIT);
    }
    return address;
  }

  public static LocalWitnesses buildPqWitnesses(List<PqEntryConfig> pqEntries,
                                                String accountAddress) {
    // Each entry is an object { scheme = "<PQScheme>", key | seed = "<hex>" }
    // so a single node can host SRs running different PQ algorithms (e.g.
    // Falcon-512 and ML-DSA-44 side by side). `key` carries the expanded
    // priv‖pub hex (any scheme); `seed` carries the keygen seed hex and is
    // accepted only when PQSchemeRegistry.isSeedDeterministic(scheme) is true.
    List<PqKeypair> pqKeypairs = new ArrayList<>(pqEntries.size());
    for (int i = 0; i < pqEntries.size(); i++) {
      pqKeypairs.add(buildPqKeypair(i, pqEntries.get(i)));
    }
    return initFromPQOnly(pqKeypairs, accountAddress);
  }

  private static PqKeypair buildPqKeypair(int index, PqEntryConfig entry) {
    // Structural validation (scheme present, exactly one of key/seed) is done
    // up front in LocalWitnessPqConfig.postProcess(); here the entry is already
    // known to name a scheme and define exactly one of key or seed.
    PQScheme scheme = resolveScheme(index, entry.getScheme());
    return entry.hasKey()
        ? keypairFromKey(index, scheme, entry.getKey())
        : keypairFromSeed(index, scheme, entry.getSeed());
  }

  private static PQScheme resolveScheme(int index, String schemeName) {
    PQScheme scheme;
    try {
      scheme = PQScheme.valueOf(schemeName);
    } catch (IllegalArgumentException e) {
      throw witnessError("invalid %s[%d].scheme: %s", PQ_KEYS_PATH, index, schemeName);
    }
    if (!PQSchemeRegistry.contains(scheme)) {
      throw witnessError("unsupported %s[%d].scheme: %s; registered schemes: %s",
          PQ_KEYS_PATH, index, schemeName, PQSchemeRegistry.registeredSchemes());
    }
    return scheme;
  }

  /**
   * Build a keypair from a `key` entry: the expanded {@code priv‖pub} hex, or —
   * for schemes whose public key can be recovered — the priv-only hex.
   */
  private static PqKeypair keypairFromKey(int index, PQScheme scheme, String rawKey) {
    int privHexLen = PQSchemeRegistry.getPrivateKeyLength(scheme) * 2;
    int extHexLen = privHexLen + PQSchemeRegistry.getPublicKeyLength(scheme) * 2;
    boolean canRecoverPk = PQSchemeRegistry.canDerivePublicKey(scheme);
    String stripped = stripHexPrefix(rawKey);
    int len = stripped.length();
    boolean shortForm = canRecoverPk && len == privHexLen;
    if (len != extHexLen && !shortForm) {
      String expected = canRecoverPk
          ? String.format("%d (priv-only) or %d (extended priv‖pub)", privHexLen, extHexLen)
          : String.format("%d (extended priv‖pub)", extHexLen);
      throw witnessError("%s[%d].key must be %s hex chars for %s, actual: %d",
          PQ_KEYS_PATH, index, expected, scheme, len);
    }
    String privHex = stripped.substring(0, privHexLen);
    if (!shortForm) {
      return new PqKeypair(scheme, privHex, stripped.substring(privHexLen));
    }
    byte[] privBytes = decodeHex(privHex, index, scheme, "key");
    byte[] pubBytes;
    try {
      pubBytes = PQSchemeRegistry.derivePublicKey(scheme, privBytes);
    } catch (RuntimeException e) {
      throw witnessError("%s[%d].key cannot recover public key for %s: %s",
          PQ_KEYS_PATH, index, scheme, e.getMessage());
    }
    return new PqKeypair(scheme, privHex, Hex.toHexString(pubBytes));
  }

  /**
   * Build a keypair from a `seed` entry by running the scheme's keygen.
   */
  private static PqKeypair keypairFromSeed(int index, PQScheme scheme, String rawSeed) {
    if (!PQSchemeRegistry.isSeedDeterministic(scheme)) {
      // Falcon's FFT-based keygen is architecture- and JVM-dependent: the
      // same seed may produce a different keypair on a different machine.
      // Warn loudly so the operator knows their witness key may drift if
      // the node is ever migrated; using `key` (expanded priv‖pub) is
      // strongly recommended for production.
      logger.warn("{} scheme {} uses non-deterministic keygen; the same seed "
          + "may produce different keys on a different JVM or architecture. "
          + "Consider using `key` with the extended priv‖pub hex instead.",
          PQ_KEYS_PATH, scheme);
    }
    int seedHexLen = PQSchemeRegistry.getSeedLength(scheme) * 2;
    String stripped = stripHexPrefix(rawSeed);
    if (stripped.length() != seedHexLen) {
      throw witnessError("%s[%d].seed must be %d hex chars for %s, actual: %d",
          PQ_KEYS_PATH, index, seedHexLen, scheme, stripped.length());
    }
    byte[] seedBytes = decodeHex(stripped, index, scheme, "seed");
    PQSignature derived = PQSchemeRegistry.fromSeed(scheme, seedBytes);
    return new PqKeypair(scheme, Hex.toHexString(derived.getPrivateKey()),
        Hex.toHexString(derived.getPublicKey()));
  }

  private static byte[] decodeHex(String hex, int index, PQScheme scheme, String field) {
    try {
      return Hex.decode(hex);
    } catch (RuntimeException e) {
      throw witnessError("%s[%d].%s is not valid hex for %s: %s",
          PQ_KEYS_PATH, index, field, scheme, e.getMessage());
    }
  }

  private static TronError witnessError(String format, Object... args) {
    return new TronError(String.format(format, args), TronError.ErrCode.WITNESS_INIT);
  }

  private static String stripHexPrefix(String hex) {
    if (hex.startsWith("0x") || hex.startsWith("0X")) {
      return hex.substring(2);
    }
    return hex;
  }
}
