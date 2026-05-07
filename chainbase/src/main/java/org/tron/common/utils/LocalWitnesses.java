/*
 * java-tron is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * java-tron is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.utils;

import com.google.common.collect.Lists;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.core.config.Parameter.ChainConstant;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "app")
public class LocalWitnesses {

  @Getter
  private List<String> privateKeys = Lists.newArrayList();

  /**
   * Pre-derived PQ private keys in hex format, one per witness. The expected
   * byte length depends on {@link #pqScheme}: 1280 bytes (2560 hex chars) for
   * FN-DSA-512. Index-aligned with {@link #pqPublicKeys}.
   *
   * <p>Configured directly (rather than derived from a seed on the node) so
   * the runtime path is not exposed to potential cross-platform floating-point
   * non-determinism in BC's Falcon keygen — operators generate the keypair
   * off-line and ship both halves to the node.
   */
  @Getter
  private List<String> pqPrivateKeys = Lists.newArrayList();

  /**
   * PQ public keys in hex format, one per witness. The expected byte length
   * depends on {@link #pqScheme}: 896 bytes (1792 hex chars) for FN-DSA-512.
   * Index-aligned with {@link #pqPrivateKeys}.
   */
  @Getter
  private List<String> pqPublicKeys = Lists.newArrayList();

  /** PQ signature scheme used by the configured {@link #pqPrivateKeys}. */
  @Getter
  private PQScheme pqScheme = PQScheme.FN_DSA_512;

  public void setPqScheme(PQScheme pqScheme) {
    if (pqScheme == null || !PQSchemeRegistry.contains(pqScheme)) {
      throw new TronError("unsupported PQ signature scheme: " + pqScheme,
          TronError.ErrCode.WITNESS_INIT);
    }
    this.pqScheme = pqScheme;
  }

  @Setter
  @Getter
  private byte[] witnessAccountAddress;

  public LocalWitnesses() {
  }

  public LocalWitnesses(String privateKey) {
    addPrivateKeys(privateKey);
  }

  public LocalWitnesses(List<String> privateKeys) {
    setPrivateKeys(privateKeys);
  }

  public void initWitnessAccountAddress(final byte[] witnessAddress,
      boolean isECKeyCryptoEngine) {
    if (witnessAddress != null) {
      this.witnessAccountAddress = witnessAddress;
    } else if (!CollectionUtils.isEmpty(privateKeys)) {
      byte[] privateKey = ByteArray.fromHexString(getPrivateKey());
      final SignInterface ecKey = SignUtils.fromPrivate(privateKey,
          isECKeyCryptoEngine);
      this.witnessAccountAddress = ecKey.getAddress();
    }
  }

  /**
   * Private key of ECKey.
   */
  public void setPrivateKeys(final List<String> privateKeys) {
    if (CollectionUtils.isEmpty(privateKeys)) {
      return;
    }
    for (String privateKey : privateKeys) {
      validate(privateKey);
    }
    this.privateKeys = privateKeys;
  }

  private void validate(String privateKey) {
    if (StringUtils.startsWithIgnoreCase(privateKey, "0X")) {
      privateKey = privateKey.substring(2);
    }

    if (StringUtils.isBlank(privateKey)
        || privateKey.length() != ChainConstant.PRIVATE_KEY_LENGTH) {
      throw new TronError(String.format("private key must be %d hex string, actual: %d",
          ChainConstant.PRIVATE_KEY_LENGTH,
          StringUtils.isBlank(privateKey) ? 0 : privateKey.length()),
          TronError.ErrCode.WITNESS_INIT);
    }
    if (!StringUtil.isHexadecimal(privateKey)) {
      throw new TronError("private key must be hex string",
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  public void addPrivateKeys(String privateKey) {
    validate(privateKey);
    this.privateKeys.add(privateKey);
  }

  /**
   * Pre-derived PQ keypairs (priv + pub) used as signing keys under
   * {@link #pqScheme}. The two lists must be the same length and index-aligned;
   * each entry must be a hex string whose byte length matches the scheme's
   * required private/public key size. Callers must therefore set the scheme
   * via {@link #setPqScheme(PQScheme)} before calling this method when
   * targeting a non-default scheme.
   */
  public void setPqKeypairs(final List<String> pqPrivateKeys,
      final List<String> pqPublicKeys) {
    if (CollectionUtils.isEmpty(pqPrivateKeys)
        && CollectionUtils.isEmpty(pqPublicKeys)) {
      return;
    }
    int privCount = pqPrivateKeys == null ? 0 : pqPrivateKeys.size();
    int pubCount = pqPublicKeys == null ? 0 : pqPublicKeys.size();
    if (privCount != pubCount) {
      throw new TronError(String.format(
          "PQ keypair list size mismatch: priv=%d, pub=%d", privCount, pubCount),
          TronError.ErrCode.WITNESS_INIT);
    }
    int expectedPrivLen = PQSchemeRegistry.getPrivateKeyLength(pqScheme);
    int expectedPubLen = PQSchemeRegistry.getPublicKeyLength(pqScheme);
    for (int i = 0; i < privCount; i++) {
      validatePqKey(pqPrivateKeys.get(i), expectedPrivLen, "PQ private key");
      validatePqKey(pqPublicKeys.get(i), expectedPubLen, "PQ public key");
    }
    this.pqPrivateKeys = pqPrivateKeys;
    this.pqPublicKeys = pqPublicKeys;
  }

  private static void validatePqKey(String key, int expectedLen, String label) {
    String hex = key;
    // Match downstream ByteArray.fromHexString, which only strips lowercase "0x".
    if (StringUtils.startsWith(hex, "0x")) {
      hex = hex.substring(2);
    }
    int expectedHexLen = expectedLen * 2;
    if (StringUtils.isBlank(hex) || hex.length() != expectedHexLen) {
      throw new TronError(String.format("%s must be %d hex chars, actual: %d",
          label, expectedHexLen, StringUtils.isBlank(hex) ? 0 : hex.length()),
          TronError.ErrCode.WITNESS_INIT);
    }
    if (!StringUtil.isHexadecimal(hex)) {
      throw new TronError(label + " must be hex string",
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  //get the first one recently
  public String getPrivateKey() {
    if (CollectionUtils.isEmpty(privateKeys)) {
      logger.warn("PrivateKey is null.");
      return null;
    }
    return privateKeys.get(0);
  }

  public byte[] getPublicKey() {
    if (CollectionUtils.isEmpty(privateKeys)) {
      logger.warn("PrivateKey is null.");
      return null;
    }
    byte[] privateKey = ByteArray.fromHexString(getPrivateKey());
    final ECKey ecKey = ECKey.fromPrivate(privateKey);
    return ecKey.getAddress();
  }

}
