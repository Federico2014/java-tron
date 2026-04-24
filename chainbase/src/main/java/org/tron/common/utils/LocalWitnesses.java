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
import org.tron.common.crypto.pqc.MLDSA65;
import org.tron.core.config.Parameter.ChainConstant;
import org.tron.core.exception.TronError;

@Slf4j(topic = "app")
public class LocalWitnesses {

  @Getter
  private List<String> privateKeys = Lists.newArrayList();

  /** ML-DSA-65 seed values in hex format (64 hex chars = 32 bytes). */
  @Getter
  private List<String> pqSeeds = Lists.newArrayList();

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

  /** ML-DSA-65 seed values (32 bytes = 64 hex chars). Keys are derived from seeds. */
  public void setPqSeeds(final List<String> pqSeeds) {
    if (CollectionUtils.isEmpty(pqSeeds)) {
      return;
    }
    for (String seed : pqSeeds) {
      validatePqSeed(seed);
    }
    this.pqSeeds = pqSeeds;
  }

  private static void validatePqSeed(String seed) {
    String hex = seed;
    if (StringUtils.startsWithIgnoreCase(hex, "0X")) {
      hex = hex.substring(2);
    }
    int expectedHexLen = MLDSA65.SEED_LENGTH * 2;
    if (StringUtils.isBlank(hex) || hex.length() != expectedHexLen) {
      throw new TronError(String.format("ML-DSA-65 seed must be %d hex chars, actual: %d",
          expectedHexLen, StringUtils.isBlank(hex) ? 0 : hex.length()),
          TronError.ErrCode.WITNESS_INIT);
    }
    if (!StringUtil.isHexadecimal(hex)) {
      throw new TronError("ML-DSA-65 seed must be hex string",
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
