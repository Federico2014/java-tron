package org.tron.core;

import static org.tron.core.zksnark.LibrustzcashTest.librustzcashInitZksnarkParams;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI;
import org.tron.api.GrpcAPI.BytesMessage;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletSolidityGrpc;
import org.tron.api.WalletSolidityGrpc.WalletSolidityBlockingStub;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.Hash;
import org.tron.core.exception.ZksnarkException;
import org.tron.core.zen.address.DiversifierT;
import org.tron.core.zen.address.ExpandedSpendingKey;
import org.tron.core.zen.address.FullViewingKey;
import org.tron.core.zen.address.IncomingViewingKey;
import org.tron.core.zen.address.KeyIo;
import org.tron.core.zen.address.PaymentAddress;
import org.tron.core.zen.address.SpendingKey;
import org.tron.core.zen.note.Note;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Result.contractResult;
import org.tron.protos.Protocol.TransactionInfo;
import org.tron.protos.contract.SmartContractOuterClass;
import stest.tron.wallet.common.client.Parameter;
import stest.tron.wallet.common.client.WalletClient;
import stest.tron.wallet.common.client.utils.PublicMethed;

@Slf4j
public class ShieldedTRC20AirdropTest {

  private static ManagedChannel channelFull = null;
  private static WalletGrpc.WalletBlockingStub blockingStubFull = null;
  private static ManagedChannel channelSolidity = null;
  private static WalletSolidityGrpc.WalletSolidityBlockingStub blockingStubSolidity = null;
  private static String fullnode = "34.220.77.106:50051";
  private static String soliditynode = "52.15.93.92:50061";
  private static String trc20ContractAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
  private static String shieldedTRC20ContractAddress = "TQEuSEVRk1GtfExm5q9T8a1w84GvgQJ13V";
  private static String privateKey =
      "200378cd3a7e109f3a862b962d21f7784443412555cc397984b935f34fbf9b84";
  private static String pubAddress = "TVRU7mHANTwKZdyRYnWW5pJpHrVApbkF97";
  private static BigInteger scalingFactorBi;
  private static String spendingKey =
      "028f05899acc1411ba071f78b4d264e678d1d7a0af2a8928313f6d6d371d5e39";

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
    scalingFactorBi = getScalingFactorBi();
    librustzcashInitZksnarkParams();
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

  @Test
  public void setAllowance() {
    byte[] contractAddress = WalletClient
        .decodeFromBase58Check(trc20ContractAddress);
    byte[] shieldedContractAddress = WalletClient
        .decodeFromBase58Check(shieldedTRC20ContractAddress);
    byte[] shieldedContractAddressPadding = new byte[32];
    System.arraycopy(shieldedContractAddress, 0, shieldedContractAddressPadding, 11, 21);
    logger.info("shielded contract addr " + ByteArray.toHexString(shieldedContractAddressPadding));
    byte[] valueBytes = longTo32Bytes(24165000000L);
    String input = Hex.toHexString(ByteUtil.merge(shieldedContractAddressPadding, valueBytes));
    PublicMethed.waitProduceNextBlock(blockingStubFull);
    byte[] callerAddress = WalletClient.decodeFromBase58Check(pubAddress);
    String txid = PublicMethed.triggerContract(contractAddress,
        "approve(address,uint256)",
        input,
        true,
        0L,
        10000000L,
        callerAddress,
        privateKey,
        blockingStubFull);
    PublicMethed.waitProduceNextBlock(blockingStubFull);
    Optional<TransactionInfo> infoById = PublicMethed
        .getTransactionInfoById(txid, blockingStubFull);
    Assert.assertEquals(
        Transaction.Result.contractResult.SUCCESS, infoById.get().getReceipt().getResult());
  }

  @Test
  public void airDrop() throws IOException, ZksnarkException {
    String inputPath = "./foreign_address_9.txt";
    File input = new File(inputPath);
    InputStreamReader reader = new InputStreamReader(new FileInputStream(input));
    BufferedReader br = new BufferedReader(reader);

    FileWriter out = new FileWriter("./foreign_result.txt", true);
    FileWriter outErrorAddress = new FileWriter("./foreign_error_address.txt", true);

    String line = "";
    String result = "";
    int cnt = 13494;
    int success = 0;
    int fail = 0;
    line = br.readLine();
    int len = line.length();
    while (line != null) {
      while (line.trim().length() != 81) {
        outErrorAddress.write(line + "\n");
        outErrorAddress.flush();
        line = br.readLine();
      }
      result = airDropByMint(1000000, line.trim());
      String[] splits = result.split(" ");
      if (splits[0].equals("1")) {
        success++;
      } else {
        fail++;
      }
      out.write(cnt + " " + result + "\n");
      out.flush();
      logger.info(cnt + " " + result);
      line = br.readLine();
      logger.info("total: " + cnt + ", success: " + success + ", fail: " + fail);
      cnt++;
    }
    out.close();
    outErrorAddress.close();
  }

  @Test
  public void reAirDrop() throws IOException, ZksnarkException {
    String inputPath = "./re_airdrop_foreign_result_4.txt";
    File input = new File(inputPath);
    InputStreamReader reader = new InputStreamReader(new FileInputStream(input));
    BufferedReader br = new BufferedReader(reader);

    FileWriter out = new FileWriter("./re_airdrop_foreign_result_5.txt", true);
    long amount = 1000000L;
    String line = "";
    String result = "";
    int cnt = 1;
    int success = 0;
    int fail = 0;
    int resentSuccess = 0;
    int resentFail = 0;
    line = br.readLine();
    while (line != null) {
      logger.info("line: " + line);
      String[] splits = line.split(" ");
      String txid = splits[2];
      String paymentAddress = splits[3];
      Optional<TransactionInfo> infoById = getTransactionInfoByIdSolidity(txid,
          blockingStubSolidity);
      if (infoById.isPresent()) {
        if (contractResult.SUCCESS != infoById.get().getReceipt().getResult()) {
          String mintResult = airDropByMint(amount, paymentAddress);
          String[] splits2 = mintResult.split(" ");
          if (splits2[0].equals("1")) {
            success++;
            resentSuccess++;
          } else {
            fail++;
            resentFail++;
          }
          result = cnt + " " + mintResult;
        } else {
          success++;
          if (splits[1].equals("0")) {
            result = splits[0] + " 1 " + splits[2] + " " + splits[3];
          } else {
            result = line;
          }
        }
      } else {  //txid is not found
        String mintResult = airDropByMint(amount, paymentAddress);
        String[] splits2 = mintResult.split(" ");
        if (splits2[0].equals("1")) {
          success++;
          resentSuccess++;
        } else {
          fail++;
          resentFail++;
        }
        result = cnt + " " + mintResult;
      }

      out.write(result + "\n");
      out.flush();
      logger.info("total: " + cnt + ", success: " + success + ", fail: " + fail);
      logger.info("resentSucess: " + resentSuccess + ", resentFail: " + resentFail);
      line = br.readLine();
      cnt++;
    }
    out.close();
  }

  @Test
  public void printPaymentAddress() throws ZksnarkException {
    SpendingKey sk = SpendingKey.decode(spendingKey);
    FullViewingKey fullViewingKey = sk.fullViewingKey();
    IncomingViewingKey incomingViewingKey = fullViewingKey.inViewingKey();
    PaymentAddress paymentAddress = incomingViewingKey.address(DiversifierT.random()).get();
    logger.info(KeyIo.encodePaymentAddress(paymentAddress));
    logger.info(Hex.toHexString(DiversifierT.random().getData()));
  }

  @Test
  public void printSpendingKey() throws ZksnarkException {
    SpendingKey sk = SpendingKey.random();
    logger.info(Hex.toHexString(sk.value));
  }


  @Test
  public void testSolidity() {
    String txid = "1a9fc434fb1eea96fc9b1f445968fb9f404ad3be80288702ec8d0b1892756445";
    String result = "";
    BytesMessage.Builder byteBuilder = BytesMessage.newBuilder();
    byteBuilder.setValue(ByteString.copyFrom(ByteUtil.hexToBytes(txid)));
    if (contractResult.SUCCESS == blockingStubSolidity
        .getTransactionInfoById(byteBuilder.build()).getReceipt().getResult()) {
      result = "1 " + txid;
    } else {
      result = "0 " + txid;
    }
    logger.info("solidity: " + result);
  }

  @Test
  public void showOvk() throws ZksnarkException {
    String spendingKey = "028f05899acc1411ba071f78b4d264e678d1d7a0af2a8928313f6d6d371d5e39";
    SpendingKey sk = SpendingKey.decode(spendingKey);
    ExpandedSpendingKey expsk = sk.expandedSpendingKey();
    byte[] ovk = expsk.getOvk();
    logger.info("ovk: " + Hex.toHexString(ovk));
  }

  private String airDropByMint(long fromAmount, String paymentAddress) throws ZksnarkException {

    SpendingKey sk = SpendingKey.decode(spendingKey);
    ExpandedSpendingKey expsk = sk.expandedSpendingKey();
    byte[] ovk = expsk.getOvk();

    //ReceiveNote
    GrpcAPI.ReceiveNote.Builder revNoteBuilder = GrpcAPI.ReceiveNote.newBuilder();
    long revValue = fromAmount;
    byte[] memo = "TRON Airdrop 1 Shielded USDT".getBytes();
    byte[] rcm = Note.generateR();
    GrpcAPI.Note revNote = getNote(revValue, paymentAddress, rcm, memo);
    revNoteBuilder.setNote(revNote);

    byte[] contractAddress = WalletClient.decodeFromBase58Check(shieldedTRC20ContractAddress);
    GrpcAPI.PrivateShieldedTRC20Parameters.Builder paramBuilder = GrpcAPI
        .PrivateShieldedTRC20Parameters.newBuilder();
    paramBuilder.setOvk(ByteString.copyFrom(ovk));
    paramBuilder.setFromAmount(getScaledPublicAmount(fromAmount));
    paramBuilder.addShieldedReceives(revNoteBuilder.build());
    paramBuilder.setShieldedTRC20ContractAddress(ByteString.copyFrom(contractAddress));

    GrpcAPI.ShieldedTRC20Parameters trc20MintParams = blockingStubFull
        .createShieldedContractParameters(paramBuilder.build());

    byte[] callerAddress = WalletClient.decodeFromBase58Check(pubAddress);
    String txid = triggerMint(blockingStubFull, contractAddress, callerAddress, privateKey,
        trc20MintParams.getTriggerContractInput());

    String result = txid + " " + paymentAddress;
    return result;
  }

  private String getScaledPublicAmount(long amount) {
    BigInteger result = BigInteger.valueOf(amount).multiply(scalingFactorBi);
    return result.toString();
  }

  private GrpcAPI.Note getNote(long value, String paymentAddress, byte[] rcm, byte[] memo) {
    GrpcAPI.Note.Builder noteBuilder = GrpcAPI.Note.newBuilder();
    noteBuilder.setValue(value);
    noteBuilder.setPaymentAddress(paymentAddress);
    noteBuilder.setRcm(ByteString.copyFrom(rcm));
    noteBuilder.setMemo(ByteString.copyFrom(memo));
    return noteBuilder.build();
  }

  private String triggerMint(WalletGrpc.WalletBlockingStub blockingStubFull, byte[] contractAddress,
      byte[] callerAddress, String privateKey, String input) {
    String methodSign = "mint(uint256,bytes32[9],bytes32[2],bytes32[21])";
    byte[] selector = new byte[4];
    System.arraycopy(Hash.sha3(methodSign.getBytes()), 0, selector, 0, 4);
    String txid = PublicMethed.triggerContract(contractAddress,
        "mint(uint256,bytes32[9],bytes32[2],bytes32[21])",
        input,
        true,
        0L, 10000000L,
        callerAddress, privateKey,
        blockingStubFull);
    PublicMethed.waitProduceNextBlock(blockingStubFull);
//    PublicMethed.waitProduceNextBlock(blockingStubFull);
//    PublicMethed.waitProduceNextBlock(blockingStubFull);
    Optional<TransactionInfo> infoById = PublicMethed
        .getTransactionInfoById(txid, blockingStubFull);

//    BytesMessage.Builder byteBuilder = BytesMessage.newBuilder();
//    byteBuilder.setValue(ByteString.copyFrom(ByteUtil.hexToBytes(txid)));
//    if (contractResult.SUCCESS == blockingStubSolidity
//        .getTransactionInfoById(byteBuilder.build()).getReceipt().getResult()) {
//      return "1 " + txid;
//    } else
//      return "0 " + txid;

    if (contractResult.SUCCESS == infoById.get().getReceipt().getResult()) {
      return "1 " + txid;
    } else {
      return "0 " + txid;
    }
  }

  //  @Ignore
  @Test
  public void testScanShieldedTRC20NotesbyIvk() throws ZksnarkException {
    int statNum = 24380600;
    int endNum = 24381600;

    byte[] contractAddress = WalletClient
        .decodeFromBase58Check(shieldedTRC20ContractAddress);
    SpendingKey sk = SpendingKey.decode(spendingKey);
    FullViewingKey fvk = sk.fullViewingKey();
    byte[] ivk = fvk.inViewingKey().value;
    GrpcAPI.IvkDecryptTRC20Parameters.Builder paramBuilder = GrpcAPI
        .IvkDecryptTRC20Parameters.newBuilder();
    logger.info(Hex.toHexString(contractAddress));
    logger.info(Hex.toHexString(ivk));
    logger.info(Hex.toHexString(fvk.getAk()));
    logger.info(Hex.toHexString(fvk.getNk()));

    paramBuilder.setAk(ByteString.copyFrom(fvk.getAk()));
    paramBuilder.setNk(ByteString.copyFrom(fvk.getNk()));
    paramBuilder.setIvk(ByteString.copyFrom(ivk));
    paramBuilder.setStartBlockIndex(statNum);
    paramBuilder.setEndBlockIndex(endNum);
    paramBuilder.setShieldedTRC20ContractAddress(ByteString.copyFrom(contractAddress));
    GrpcAPI.DecryptNotesTRC20 scannedNotes = blockingStubFull.scanShieldedTRC20NotesByIvk(
        paramBuilder.build());
    logger.info("result");
    logger.info("size: " + scannedNotes.getNoteTxsList().size());
    for (GrpcAPI.DecryptNotesTRC20.NoteTx noteTx : scannedNotes.getNoteTxsList()) {
      logger.info(noteTx.toString());
    }
  }

  @Test
  public void testscanShieldedTRC20NotesbyOvk() throws ZksnarkException {
//    int statNum = 10800;
//    int endNum = 10850;

    //transfer 2v2
//    int statNum = 45423;
//    int endNum = 45447;

    //burn1v1
//    int statNum = 45900;
//    int endNum = 45920;

    //burn1v2
    int statNum = 24534142;
    int endNum = 24534144;

    librustzcashInitZksnarkParams();
    byte[] contractAddress = WalletClient
        .decodeFromBase58Check(shieldedTRC20ContractAddress);
    SpendingKey sk = SpendingKey.decode(spendingKey);
    FullViewingKey fvk = sk.fullViewingKey();
    GrpcAPI.OvkDecryptTRC20Parameters.Builder paramBuilder = GrpcAPI.OvkDecryptTRC20Parameters
        .newBuilder();
    logger.info(Hex.toHexString(contractAddress));
    logger.info(Hex.toHexString(fvk.getOvk()));

    paramBuilder.setOvk(ByteString.copyFrom(fvk.getOvk()));
    paramBuilder.setStartBlockIndex(statNum);
    paramBuilder.setEndBlockIndex(endNum);
    paramBuilder.setShieldedTRC20ContractAddress(ByteString.copyFrom(contractAddress));
    GrpcAPI.DecryptNotesTRC20 scannedNotes = blockingStubFull.scanShieldedTRC20NotesByOvk(
        paramBuilder.build());
    logger.info("result");
    logger.info("size: " + scannedNotes.getNoteTxsList().size());
    for (GrpcAPI.DecryptNotesTRC20.NoteTx noteTx : scannedNotes.getNoteTxsList()) {
      logger.info(noteTx.toString());
      logger.info("txid: " + Hex.toHexString(noteTx.getTxid().toByteArray()));
    }
  }


  public static Optional<TransactionInfo> getTransactionInfoByIdSolidity(String txId,
      WalletSolidityBlockingStub blockingStubSolidity) {
    ByteString bsTxid = ByteString.copyFrom(ByteArray.fromHexString(txId));
    BytesMessage request = BytesMessage.newBuilder().setValue(bsTxid).build();
    TransactionInfo transactionInfo;
    transactionInfo = blockingStubSolidity.getTransactionInfoById(request);
    return Optional.ofNullable(transactionInfo);
  }

  private static BigInteger getScalingFactorBi() {
    byte[] contractAddress = WalletClient
        .decodeFromBase58Check(shieldedTRC20ContractAddress);
    byte[] scalingFactorBytes = triggerGetScalingFactor(blockingStubFull, contractAddress);
    return ByteUtil.bytesToBigInteger(scalingFactorBytes);
  }

  private static byte[] triggerGetScalingFactor(WalletGrpc.WalletBlockingStub blockingStubFull,
      byte[] contractAddress) {
    String methodSign = "scalingFactor()";
    byte[] selector = new byte[4];
    System.arraycopy(Hash.sha3(methodSign.getBytes()), 0, selector, 0, 4);
    SmartContractOuterClass.TriggerSmartContract.Builder triggerBuilder = SmartContractOuterClass
        .TriggerSmartContract.newBuilder();
    triggerBuilder.setContractAddress(ByteString.copyFrom(contractAddress));
    triggerBuilder.setData(ByteString.copyFrom(selector));
    GrpcAPI.TransactionExtention trxExt2 = blockingStubFull.triggerConstantContract(
        triggerBuilder.build());
    List<ByteString> list = trxExt2.getConstantResultList();
    byte[] result = new byte[0];
    for (ByteString bs : list) {
      result = ByteUtil.merge(result, bs.toByteArray());
    }
    Assert.assertEquals(32, result.length);
    System.out.println(ByteArray.toHexString(result));
    return result;
  }

  private byte[] longTo32Bytes(long value) {
    byte[] longBytes = ByteArray.fromLong(value);
    byte[] zeroBytes = new byte[24];
    return ByteUtil.merge(zeroBytes, longBytes);
  }

  private long bytes32Tolong(byte[] value) {
    return ByteArray.toLong(value);
  }


}
