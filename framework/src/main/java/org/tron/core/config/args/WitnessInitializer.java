package org.tron.core.config.args;

import com.typesafe.config.Config;
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
import org.tron.core.Constant;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.TronError;
import org.tron.keystore.Credentials;
import org.tron.keystore.WalletUtils;
import org.tron.protos.Protocol.PQScheme;

@Slf4j
public class WitnessInitializer {

  private final Config config;

  private LocalWitnesses localWitnesses;

  public WitnessInitializer(Config config) {
    this.config = config;
    this.localWitnesses = new LocalWitnesses();
  }

  public LocalWitnesses initLocalWitnesses() {
    if (!Args.PARAMETER.isWitness()) {
      return localWitnesses;
    }

    // Load PQ keypairs independently so a node can host a mix of ECDSA and PQ
    // SRs (e.g. during a rolling migration where some SRs have moved to PQ and
    // others have not yet). The PQ side has its own *AccountAddress key
    // (localPqWitnessAccountAddress) so mixed-mode configs do not have to drop
    // the legacy override for the ECDSA side.
    List<PqEntryConfig> pqEntries = parsePqEntries();
    LocalWitnesses pqWitnesses = null;
    if (!pqEntries.isEmpty()) {
      pqWitnesses = buildPqWitnesses(pqEntries, getPqWitnessAccountAddress());
    }

    boolean hasEcdsa = tryInitFromCommandLine()
        || tryInitFromConfig()
        || tryInitFromKeystore();

    if (!hasEcdsa && pqWitnesses == null) {
      return localWitnesses;
    }

    if (hasEcdsa && pqWitnesses != null) {
      // Carry both identities so a node hosting one ECDSA SR + one PQ SR can
      // match either schedule slot. Consumers consult the field that matches
      // their signing path (ECDSA address for ECDSA sigs, PQ address for PQ).
      localWitnesses.setPqKeypairs(pqWitnesses.getPqKeypairs());
      localWitnesses.initPqWitnessAccountAddress(
          pqWitnesses.getPqWitnessAccountAddress());
    } else if (pqWitnesses != null) {
      localWitnesses = pqWitnesses;
    }

    return localWitnesses;
  }

  private String getPqWitnessAccountAddress() {
    return config.hasPath(Constant.LOCAL_PQ_WITNESS_ACCOUNT_ADDRESS)
        ? config.getString(Constant.LOCAL_PQ_WITNESS_ACCOUNT_ADDRESS) : null;
  }

  private List<PqEntryConfig> parsePqEntries() {
    if (!config.hasPath(Constant.LOCAL_WITNESS_PQ_KEYS)) {
      return new ArrayList<>();
    }
    List<? extends Config> raw = config.getConfigList(Constant.LOCAL_WITNESS_PQ_KEYS);
    List<PqEntryConfig> entries = new ArrayList<>(raw.size());
    for (int i = 0; i < raw.size(); i++) {
      Config entry = raw.get(i);
      String scheme = entry.hasPath("scheme") ? entry.getString("scheme") : null;
      String key = entry.hasPath("key") ? entry.getString("key") : null;
      String seed = entry.hasPath("seed") ? entry.getString("seed") : null;
      entries.add(new PqEntryConfig(i, scheme, key, seed));
    }
    return entries;
  }

  private static LocalWitnesses buildPqWitnesses(List<PqEntryConfig> pqEntries,
                                                 String accountAddress) {
    // Each entry is an object { scheme = "<PQScheme>", key | seed = "<hex>" }
    // so a single node can host SRs running different PQ algorithms (e.g.
    // Falcon-512 and ML-DSA-44 side by side). `key` carries the expanded
    // priv‖pub hex (any scheme); `seed` carries the keygen seed hex and is
    // accepted only when PQSchemeRegistry.isSeedDeterministic(scheme) is true.
    String path = Constant.LOCAL_WITNESS_PQ_KEYS;
    List<PqKeypair> pqKeypairs = new ArrayList<>(pqEntries.size());
    for (PqEntryConfig entry : pqEntries) {
      int i = entry.getIndex();
      if (entry.getScheme() == null) {
        throw new TronError(String.format(
            "%s[%d] must define `scheme`", path, i),
            TronError.ErrCode.WITNESS_INIT);
      }
      if (entry.hasKey() == entry.hasSeed()) {
        throw new TronError(String.format(
            "%s[%d] must define exactly one of `key` or `seed`", path, i),
            TronError.ErrCode.WITNESS_INIT);
      }
      PQScheme scheme;
      try {
        scheme = PQScheme.valueOf(entry.getScheme());
      } catch (IllegalArgumentException e) {
        throw new TronError(String.format("invalid %s[%d].scheme: %s",
            path, i, entry.getScheme()),
            TronError.ErrCode.WITNESS_INIT);
      }
      if (!PQSchemeRegistry.contains(scheme)) {
        throw new TronError(String.format(
            "unsupported %s[%d].scheme: %s; registered schemes: %s",
            path, i, entry.getScheme(), PQSchemeRegistry.registeredSchemes()),
            TronError.ErrCode.WITNESS_INIT);
      }
      String privHex;
      String pubHex;
      if (entry.hasKey()) {
        int privHexLen = PQSchemeRegistry.getPrivateKeyLength(scheme) * 2;
        int extHexLen = privHexLen + PQSchemeRegistry.getPublicKeyLength(scheme) * 2;
        boolean canRecoverPk = PQSchemeRegistry.canDerivePublicKey(scheme);
        String stripped = stripHexPrefix(entry.getKey());
        int len = stripped == null ? 0 : stripped.length();
        boolean shortForm = canRecoverPk && len == privHexLen;
        if (stripped == null || (len != extHexLen && !shortForm)) {
          String expected = canRecoverPk
              ? String.format("%d (priv-only) or %d (extended priv‖pub)",
                  privHexLen, extHexLen)
              : String.format("%d (extended priv‖pub)", extHexLen);
          throw new TronError(String.format(
              "%s[%d].key must be %s hex chars for %s, actual: %d",
              path, i, expected, scheme, len),
              TronError.ErrCode.WITNESS_INIT);
        }
        privHex = stripped.substring(0, privHexLen);
        if (shortForm) {
          byte[] privBytes;
          try {
            privBytes = Hex.decode(privHex);
          } catch (RuntimeException e) {
            throw new TronError(String.format(
                "%s[%d].key is not valid hex for %s: %s",
                path, i, scheme, e.getMessage()),
                TronError.ErrCode.WITNESS_INIT);
          }
          byte[] pubBytes;
          try {
            pubBytes = PQSchemeRegistry.derivePublicKey(scheme, privBytes);
          } catch (RuntimeException e) {
            throw new TronError(String.format(
                "%s[%d].key cannot recover public key for %s: %s",
                path, i, scheme, e.getMessage()),
                TronError.ErrCode.WITNESS_INIT);
          }
          pubHex = Hex.toHexString(pubBytes);
        } else {
          pubHex = stripped.substring(privHexLen);
        }
      } else {
        if (!PQSchemeRegistry.isSeedDeterministic(scheme)) {
          // Falcon's FFT-based keygen drifts across JVMs/architectures, so
          // seed-only config would produce different witness keys on
          // different nodes. Force operators to commit the expanded keypair.
          throw new TronError(String.format(
              "%s[%d].seed is not supported for %s (non-deterministic keygen); "
                  + "use `key` with the extended priv‖pub hex instead",
              path, i, scheme),
              TronError.ErrCode.WITNESS_INIT);
        }
        int seedHexLen = PQSchemeRegistry.getSeedLength(scheme) * 2;
        String stripped = stripHexPrefix(entry.getSeed());
        if (stripped == null || stripped.length() != seedHexLen) {
          throw new TronError(String.format(
              "%s[%d].seed must be %d hex chars for %s, actual: %d",
              path, i, seedHexLen, scheme,
              stripped == null ? 0 : stripped.length()),
              TronError.ErrCode.WITNESS_INIT);
        }
        byte[] seedBytes;
        try {
          seedBytes = Hex.decode(stripped);
        } catch (RuntimeException e) {
          throw new TronError(String.format(
              "%s[%d].seed is not valid hex for %s: %s",
              path, i, scheme, e.getMessage()),
              TronError.ErrCode.WITNESS_INIT);
        }
        PQSignature derived = PQSchemeRegistry.fromSeed(scheme, seedBytes);
        privHex = Hex.toHexString(derived.getPrivateKey());
        pubHex = Hex.toHexString(derived.getPublicKey());
      }
      pqKeypairs.add(new PqKeypair(scheme, privHex, pubHex));
    }
    return initFromPQOnly(pqKeypairs, accountAddress);
  }

  private static String stripHexPrefix(String hex) {
    if (hex == null) {
      return null;
    }
    if (hex.startsWith("0x") || hex.startsWith("0X")) {
      return hex.substring(2);
    }
    return hex;
  }

  private boolean tryInitFromCommandLine() {
    if (StringUtils.isBlank(Args.PARAMETER.privateKey)) {
      return false;
    }

    byte[] witnessAddress = null;
    this.localWitnesses = new LocalWitnesses(Args.PARAMETER.privateKey);
    if (StringUtils.isNotEmpty(Args.PARAMETER.witnessAddress)) {
      witnessAddress = Commons.decodeFromBase58Check(Args.PARAMETER.witnessAddress);
      if (witnessAddress == null) {
        throw new TronError("LocalWitnessAccountAddress format from cmd is incorrect",
            TronError.ErrCode.WITNESS_INIT);
      }
      logger.debug("Got localWitnessAccountAddress from cmd");
    }

    this.localWitnesses.initWitnessAccountAddress(witnessAddress,
        Args.PARAMETER.isECKeyCryptoEngine());
    logger.debug("Got privateKey from cmd");
    return true;
  }

  private boolean tryInitFromConfig() {
    if (!config.hasPath(Constant.LOCAL_WITNESS) || config.getStringList(Constant.LOCAL_WITNESS)
        .isEmpty()) {
      return false;
    }

    List<String> localWitness = config.getStringList(Constant.LOCAL_WITNESS);
    this.localWitnesses.setPrivateKeys(localWitness);
    logger.debug("Got privateKey from config.conf");
    byte[] witnessAddress = getWitnessAddress();
    this.localWitnesses.initWitnessAccountAddress(witnessAddress,
        Args.PARAMETER.isECKeyCryptoEngine());
    return true;
  }

  private boolean tryInitFromKeystore() {
    if (!config.hasPath(Constant.LOCAL_WITNESS_KEYSTORE)
        || config.getStringList(Constant.LOCAL_WITNESS_KEYSTORE).isEmpty()) {
      return false;
    }

    List<String> localWitness = config.getStringList(Constant.LOCAL_WITNESS_KEYSTORE);
    if (localWitness.size() > 1) {
      logger.warn(
          "Multiple keystores detected. Only the first keystore will be used as witness, all "
              + "others will be ignored.");
    }

    List<String> privateKeys = new ArrayList<>();
    String fileName = System.getProperty("user.dir") + "/" + localWitness.get(0);
    String password;
    if (StringUtils.isEmpty(Args.PARAMETER.password)) {
      System.out.println("Please input your password.");
      password = WalletUtils.inputPassword();
    } else {
      password = Args.PARAMETER.password;
      Args.PARAMETER.password = null;
    }

    try {
      Credentials credentials = WalletUtils
          .loadCredentials(password, new File(fileName));
      SignInterface sign = credentials.getSignInterface();
      String prikey = ByteArray.toHexString(sign.getPrivateKey());
      privateKeys.add(prikey);
    } catch (IOException | CipherException e) {
      logger.error("Witness node start failed!");
      throw new TronError(e, TronError.ErrCode.WITNESS_KEYSTORE_LOAD);
    }

    this.localWitnesses.setPrivateKeys(privateKeys);
    byte[] witnessAddress = getWitnessAddress();
    this.localWitnesses.initWitnessAccountAddress(witnessAddress,
        Args.PARAMETER.isECKeyCryptoEngine());
    logger.debug("Got privateKey from keystore");
    return true;
  }

  /**
   * Init for PQ-only witness nodes (no legacy ECDSA key). Each PqKeypair
   * carries its own PQScheme. When {@code pqWitnessAccountAddress} is blank,
   * the address is derived from the first PQ public key via
   * {@link PQSchemeRegistry#computeAddress(PQScheme, byte[])} using that
   * entry's scheme. Only {@code pqWitnessAccountAddress} is populated; the
   * legacy ECDSA-side field stays {@code null} so downstream callers must
   * decide which identity (ECDSA vs PQ) to consult.
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

    byte[] explicit = null;
    if (StringUtils.isNotBlank(pqWitnessAccountAddress)) {
      if (pqKeypairs.size() != 1) {
        throw new TronError(
            "localPqWitnessAccountAddress can only be set when there is only one PQ keypair",
            TronError.ErrCode.WITNESS_INIT);
      }
      explicit = Commons.decodeFromBase58Check(pqWitnessAccountAddress);
      if (explicit == null) {
        throw new TronError(
            "localPqWitnessAccountAddress format is incorrect",
            TronError.ErrCode.WITNESS_INIT);
      }
      logger.debug("Got localPqWitnessAccountAddress from config.conf");
    } else {
      logger.debug("Derived PQ-only witness address from public key");
    }
    witnesses.initPqWitnessAccountAddress(explicit);
    return witnesses;
  }

  private byte[] getWitnessAddress() {
    if (!config.hasPath(Constant.LOCAL_WITNESS_ACCOUNT_ADDRESS)) {
      return null;
    }

    if (localWitnesses.getPrivateKeys().size() != 1) {
      throw new TronError(
          "LocalWitnessAccountAddress can only be set when there is only one private key",
          TronError.ErrCode.WITNESS_INIT);
    }
    byte[] witnessAddress = Commons
        .decodeFromBase58Check(config.getString(Constant.LOCAL_WITNESS_ACCOUNT_ADDRESS));
    if (witnessAddress != null) {
      logger.debug("Got localWitnessAccountAddress from config.conf");
    } else {
      throw new TronError("LocalWitnessAccountAddress format from config is incorrect",
          TronError.ErrCode.WITNESS_INIT);
    }
    return witnessAddress;
  }
}
