package org.tron.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Commons;
import org.tron.common.utils.Hash;
import stest.tron.wallet.common.client.WalletClient;

@Slf4j
public class NewTest {

  @Test
  public void checkLogTopics() {
    byte[] SHIELDED_TRC20_LOG_TOPICS = Hash.sha3(ByteArray.fromString(
        "NewLeaf(uint256,bytes32,bytes32,bytes32,bytes32[21])")); //
    Assert.assertArrayEquals(SHIELDED_TRC20_LOG_TOPICS, ByteArray
        .fromHexString("58aa407d312e8d4017790223440ca1f60c54959864d7bd1d1ed37c82f72dfc1d"));
    // ;
    logger.info(ByteArray.toHexString(SHIELDED_TRC20_LOG_TOPICS));
    byte[] SHIELDED_TRC20_LOG_TOPICS_FOR_BURN = Hash.sha3(ByteArray
        .fromString(
            "TokenBurn(address,uint256,bytes32[3])")); //
    Assert.assertArrayEquals(SHIELDED_TRC20_LOG_TOPICS_FOR_BURN, ByteArray
        .fromHexString("1daf70c304f467a9efbc9ac1ca7bfe859a478aa6c4b88131b4dbb1547029b972"));
    logger.info(ByteArray.toHexString(SHIELDED_TRC20_LOG_TOPICS_FOR_BURN));
    // "1daf70c304f467a9efbc9ac1ca7bfe859a478aa6c4b88131b4dbb1547029b972";
  }

  private String recursivelyAddComma(String s) {
    int length = s.length();
    if (length <= 3) {
      return s;
    }
    return recursivelyAddComma(s.substring(0, length - 3)).concat(",")
        .concat(s.substring(length - 3, length));
  }

  @Test
  public void formatString() {
    String str = "123456789";
    System.out.println(recursivelyAddComma(str));
  }

  @Test
  public void testD() {
    double value = 1e18D;
    System.out.println(Double.toHexString(value));
//    BigInteger big = new BigInteger(Double.toHexString(value), 16);
//    System.out.println(big.toString(10));
  }

  @Test
  public void estimateGas() {
    BigInteger multiplier = new BigInteger("1000000000000", 10);
    BigInteger totalCost = new BigInteger("100000000", 10); // 100 trx
    BigInteger gasPrice = new BigInteger("9184e72a000", 16);
    if (gasPrice.compareTo(BigInteger.valueOf(0)) > 0) {
      System.out.println("0x" + totalCost.multiply(multiplier).divide(gasPrice).toString(16));
    }
    System.out.println("0x0");
  }

  @Test
  public void testTronAddress() throws Exception {
    String privateKey = "da146374a75310b9666e834ee4ad0866d6f4035967bfc76217c5a495fff9f0d0";
    String tronAddress = "TPL66VK2gCXNCD7EJg9pgJRfqcRazjhUZY";
    String ethAddress = "0x928C9af0651632157ef27A2cf17Ca72c575a4d21";
    ECKey eckey = new ECKey(ByteArray.fromHexString(privateKey), true);
    String address = WalletClient.encode58Check(eckey.getAddress());
    System.out.println(address);
    System.out.println(tronToEthAddress(address));
  }

  // transform the Tron address to Ethereum Address
  private String tronToEthAddress(String tronAddress) throws Exception {
    byte[] tronBytes = Commons.decodeFromBase58Check(tronAddress);
    byte[] ethBytes = new byte[20];
    System.arraycopy(tronBytes, 1, ethBytes, 0, 20);
    return toChecksumAddress(ByteArray.toHexString(ethBytes));
  }

  private String toChecksumAddress(String address) throws Exception {
    StringBuffer sb = new StringBuffer();
    int nibble = 0;

    if (address.startsWith("0x")) {
      address = address.substring(2);
    }
    String hashedAddress = ByteArray
        .toHexString(Hash.sha3(address.getBytes(StandardCharsets.UTF_8)));
    sb.append("0x");
    for (int i = 0; i < address.length(); i++) {
      if ("0123456789".contains(String.valueOf(address.charAt(i)))) {
        sb.append(address.charAt(i));
      } else if ("abcdef".contains(String.valueOf(address.charAt(i)))) {
        nibble = Integer.parseInt(String.valueOf(hashedAddress.charAt(i)), 16);
        if (nibble > 7) {
          sb.append(String.valueOf(address.charAt(i)).toUpperCase());
        } else {
          sb.append(address.charAt(i));
        }
      } else {
        throw new Exception("invalid hex character in address");
      }
    }
    return sb.toString();
  }

}
