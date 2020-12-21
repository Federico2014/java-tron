package org.tron.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI.AddressPrKeyPairMessage;
import org.tron.api.GrpcAPI.EmptyMessage;
import org.tron.api.GrpcAPI.NumberMessage;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletSolidityGrpc;
import org.tron.common.utils.ByteUtil;
import org.tron.core.services.http.Util;
import org.tron.protos.Protocol;
import stest.tron.wallet.common.client.Parameter;
import stest.tron.wallet.common.client.WalletClient;

@Slf4j
public class TestAddress {

  private static ManagedChannel channelFull = null;
  private static WalletGrpc.WalletBlockingStub blockingStubFull = null;
  private static ManagedChannel channelSolidity = null;
  private static WalletSolidityGrpc.WalletSolidityBlockingStub blockingStubSolidity = null;
  private static String fullnode = "34.220.77.106:50051";
  private static String soliditynode = "127.0.0.1:50061";
  private static String trc20ContractAddress = "TFUD8x3iAZ9dF7NDCGBtSjznemEomE5rP9";
  private static String shieldedTRC20ContractAddress = "TPcKtz5TRfP4xUZSos81RmXB9K2DBqj2iu";
  private static String privateKey =
      "022b7be64a119101dbad936270c5a88440b28851dc711be7bf56d27afc015966";
  private static String pubAddress = "TSPrmJetAMo6S6RxMd4tswzeRCFVegBNig";
  private static BigInteger scalingFactorBi;

  @BeforeClass
  public static void beforeClass() {
    channelFull = ManagedChannelBuilder.forTarget(fullnode).usePlaintext(true)
        .build();
    blockingStubFull = WalletGrpc.newBlockingStub(channelFull);
    channelSolidity = ManagedChannelBuilder.forTarget(soliditynode)
        .usePlaintext(true)
        .build();
    blockingStubSolidity = WalletSolidityGrpc.newBlockingStub(channelSolidity);
    Wallet.setAddressPreFixByte(Parameter.CommonConstant.ADD_PRE_FIX_BYTE_MAINNET);
//    scalingFactorBi = getScalingFactorBi();
  }

  @AfterClass
  public static void afterClass() throws InterruptedException {
    if (channelFull != null) {
      channelFull.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }
    if (channelSolidity != null) {
      channelSolidity.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  @Ignore
  @Test
  public void printTRC20Address() {
    logger.info(Hex.toHexString(new byte[11]) + Hex
        .toHexString(WalletClient.decodeFromBase58Check(trc20ContractAddress)) + Hex
        .toHexString(ByteUtil.longTo32Bytes(2)));
  }


  //  @Ignore
  @Test
  public void testGenerateAddress() {

    //      SignInterface cryptoEngine = SignUtils.getGeneratedRandomSign(Utils.getRandom(),
//          Args.getInstance().isECKeyCryptoEngine());
//      byte[] priKey = cryptoEngine.getPrivateKey();
//      byte[] address = cryptoEngine.getAddress();
    String tmpKey = "";
    String temAddress = "";
    for (int i = 0; i < 10000; i++) {
      EmptyMessage.Builder em = EmptyMessage.newBuilder();
      AddressPrKeyPairMessage key = blockingStubFull.generateAddress(em.build());
      String keyString = key.getPrivateKey();
      String base58Address = key.getAddress();
      Assert.assertNotEquals(tmpKey, keyString);
      Assert.assertNotEquals(temAddress, base58Address);
      System.out.println(i + " " + keyString + " " + base58Address);
      tmpKey = keyString;
      temAddress = base58Address;
    }
  }

  @Test
  public void testGetBlockByNumVisible() {
    NumberMessage.Builder num = NumberMessage.newBuilder();
    num.setNum(20181145);
    Protocol.Block block = blockingStubFull.getBlockByNum(num.build());
//    System.out.println(block.toString());
    String blockData = Util.printBlock(block, false);
    System.out.println("block data: " + blockData);
  }

  public class GenerateAddress {

    @Getter
    @Setter
    private String privateKey;
    @Getter
    @Setter
    private String address;
    @Getter
    @Setter
    private String hexAddress;
  }

  @Ignore
  @Test
  public void http() throws IOException {
    String methodUrl = "https://api.trongrid.io/wallet/generateaddress";
//    String methodUrl = "http://127.0.0.1:8090/wallet/generateaddress";

    HttpURLConnection connection = null;
    String line = null;
    String tmpKey = null;
    String temAddress = null;
    BufferedReader reader = null;
    try {
      for (int i = 0; i < 10000; i++) {
//        Thread.sleep(3000);
        URL url = new URL(methodUrl);
        reader = null;
        connection = (HttpURLConnection) url.openConnection();// 根据URL生成HttpURLConnection
        connection.setRequestMethod("GET");// 默认GET请求
        connection.connect();// 建立TCP连接
        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {

          reader = new BufferedReader(
              new InputStreamReader(connection.getInputStream(), "UTF-8"));// 发送http请求
          StringBuilder result = new StringBuilder();
          // 循环读取流
          while ((line = reader.readLine()) != null) {
            result.append(line).append(System.getProperty("line.separator"));// "\n"

          }
//          System.out.println(i + " " + result.toString());
          JSONObject obj = JSON.parseObject(result.toString());
          if (obj == null) {
            continue;
          }
          String privateKey = obj.getString("privateKey");
          String addr = obj.getString("address");
          System.out.println(i + " " + privateKey + " " + addr);
          Assert.assertNotEquals(tmpKey, privateKey);
          Assert.assertNotEquals(temAddress, addr);
          tmpKey = privateKey;
          temAddress = addr;
        }
      }
    } catch (IOException e) {
//        e.printStackTrace();
      System.out.println("network exception");

    } finally {
      if (reader != null) {
        reader.close();
      }
      connection.disconnect();
    }
  }
}
