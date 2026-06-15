package org.tron.core.config.args;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Commons;
import org.tron.common.utils.LocalWitnesses;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.TronError;
import org.tron.keystore.Credentials;
import org.tron.keystore.WalletUtils;
import org.tron.protos.Protocol.PQScheme;

@Slf4j
public class WitnessInitializer {

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
            "localwitness_pq.accountAddress can only be set when there is only one PQ keypair",
            TronError.ErrCode.WITNESS_INIT);
      }
      explicit = Commons.decodeFromBase58Check(pqWitnessAccountAddress);
      if (explicit == null) {
        throw new TronError(
            "localwitness_pq.accountAddress format is incorrect",
            TronError.ErrCode.WITNESS_INIT);
      }
      logger.debug("Got localwitness_pq.accountAddress from config.conf");
    } else {
      logger.debug("Derived PQ-only witness address from public key");
    }
    witnesses.initPqWitnessAccountAddress(explicit);
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
}
