package org.tron.core.actuator;

import static org.junit.Assert.assertArrayEquals;
import static org.tron.core.db.TransactionTrace.convertToTronAddress;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Charsets;
import com.google.common.io.Files;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.core.Constant;
import org.tron.core.Wallet;
import org.tron.core.config.args.Args;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.repository.RepositoryImpl;
import org.tron.core.zksnark.SendCoinShieldTest;

@Slf4j
public class BN128PrecompiledContratsTest extends BaseTest {

  // bn128
  private static final DataWord altBN128AddAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000006");
  private static final DataWord altBN128MulAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000007");
  private static final DataWord altBN128PairingAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000008");

  private static final String OWNER_ADDRESS;

  static {
    Args.setParam(new String[]{"--output-directory", dbPath(), "--debug"}, Constant.TEST_CONF);
    OWNER_ADDRESS = Wallet.getAddressPreFixString() + "abd4b9367799eaa3197fecb144eb71de1e049abc";
  }

  @Test
  public void bn128AdditionTest() throws Exception {
    PrecompiledContract bn128Add = createPrecompiledContract(altBN128AddAddr, OWNER_ADDRESS);
    JSONArray testCases = readJsonFile("bn256Add.json");
    for (int i = 0; i < testCases.size(); i++) {
      JSONObject testCase = testCases.getJSONObject(i);
      String name = testCase.getString("Name");
      Boolean ret = testCase.getBoolean("Result");
      byte[] input = Hex.decode(testCase.getString("Input"));
      byte[] expected = Hex.decode(testCase.getString("Expected"));
      Pair<Boolean, byte[]> result = bn128Add.execute(input);
      if (result.getLeft()) {
        assertArrayEquals(String.format("BN128Add test %s failed", name), expected,
            result.getRight());
        Assert.assertNull(ret);
      } else {
        Assert.assertFalse(ret);
      }
    }
  }

  @Test
  public void bn128MultiplicationTest() throws Exception {
    PrecompiledContract bn128Mul = createPrecompiledContract(altBN128MulAddr, OWNER_ADDRESS);
    JSONArray testCases = readJsonFile("bn256ScalarMul.json");
    for (int i = 0; i < testCases.size(); i++) {
      JSONObject testCase = testCases.getJSONObject(i);
      String name = testCase.getString("Name");
      Boolean ret = testCase.getBoolean("Result");
      byte[] input = Hex.decode(testCase.getString("Input"));
      byte[] expected = Hex.decode(testCase.getString("Expected"));
      Pair<Boolean, byte[]> result = bn128Mul.execute(input);
      if (result.getLeft()) {
        assertArrayEquals(String.format("bn128Mul test %s failed", name), expected,
            result.getRight());
        Assert.assertNull(ret);
      } else {
        Assert.assertFalse(ret);
      }
    }
  }

  @Test
  public void bn128PairingTest() throws Exception {
    PrecompiledContract bn128Pairing =
        createPrecompiledContract(altBN128PairingAddr, OWNER_ADDRESS);
    JSONArray testCases = readJsonFile("bn256Pairing.json");
    for (int i = 0; i < testCases.size(); i++) {
      JSONObject testCase = testCases.getJSONObject(i);
      String name = testCase.getString("Name");
      Boolean ret = testCase.getBoolean("Result");
      byte[] input = Hex.decode(testCase.getString("Input"));
      byte[] expected = Hex.decode(testCase.getString("Expected"));
      Pair<Boolean, byte[]> result = bn128Pairing.execute(input);
      if (result.getLeft()) {
        assertArrayEquals(String.format("bn128Pairing test %s failed", name), expected,
            result.getRight());
        Assert.assertNull(ret);
      } else {
        Assert.assertFalse(ret);
      }
    }
  }

  private byte[] validPointsByte() {
    byte[] g1Point0 = ByteUtil.merge(ByteArray.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000001"),
        ByteArray.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000002"));

    byte[] g2Point0 = ByteUtil.merge(ByteArray.fromHexString(
            "0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        ByteArray.fromHexString(
            "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        ByteArray.fromHexString(
            "0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
        ByteArray.fromHexString(
            "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
    );

    byte[] g1Point1 = ByteUtil.merge(ByteArray.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000001"),
        ByteArray.fromHexString(
            "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"));

    byte[] g2Point1 = ByteUtil.merge(ByteArray.fromHexString(
            "0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        ByteArray.fromHexString(
            "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        ByteArray.fromHexString(
            "0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
        ByteArray.fromHexString(
            "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
    );

    return ByteUtil.merge(g1Point0, g2Point0, g1Point1, g2Point1);
  }

  private byte[] inValidPointsOutsideSubgroupG2() {
    byte[] g1Point0 = ByteUtil.merge(ByteArray.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000001"),
        ByteArray.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000002"));

    byte[] g2Point0 = ByteUtil.merge(ByteArray.fromHexString(
            "0x1382cd45e5674247f9c900b5c6f6cabbc189c2fabe2df0bf5acd84c97818f508"),
        ByteArray.fromHexString(
            "0x1246178655ab8f2f26956b189894b7eb93cd4215b9937e7969e44305f80f521e"),
        ByteArray.fromHexString(
            "0x08331c0a261a74e7e75db1232956663cbc88110f726159c5cba1857ecd03fa64"),
        ByteArray.fromHexString(
            "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
    );

    byte[] g1Point1 = ByteUtil.merge(ByteArray.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000001"),
        ByteArray.fromHexString(
            "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"));

    byte[] g2Point1 = ByteUtil.merge(ByteArray.fromHexString(
            "0x1382cd45e5674247f9c900b5c6f6cabbc189c2fabe2df0bf5acd84c97818f508"),
        ByteArray.fromHexString(
            "0x1246178655ab8f2f26956b189894b7eb93cd4215b9937e7969e44305f80f521e"),
        ByteArray.fromHexString(
            "0x08331c0a261a74e7e75db1232956663cbc88110f726159c5cba1857ecd03fa64"),
        ByteArray.fromHexString(
            "0x1fbf8045ce3e79b5cde4112d38bcd0efbdb1295d2eefdf58151ae309d7ded7db")
    );

    return ByteUtil.merge(g1Point0, g2Point0, g1Point1, g2Point1);
  }

  @Test
  public void bn128CorrectionTest() {
    PrecompiledContract bn128Pairing = createPrecompiledContract(altBN128PairingAddr,
        OWNER_ADDRESS);
    byte[] intput = validPointsByte();
    Pair<Boolean, byte[]> result = bn128Pairing.execute(intput);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(ByteArray.fromHexString(
        "0x0000000000000000000000000000000000000000000000000000000000000001"), result.getRight());

    intput = inValidPointsOutsideSubgroupG2();
    result = bn128Pairing.execute(intput);
    Assert.assertFalse(result.getLeft());
    Assert.assertEquals("invalid input parameters, point is not on curve",
        new String(result.getRight(), StandardCharsets.US_ASCII));
  }

  @Test
  public void bn128AdditionRandomTest() {
    PrecompiledContract bn128Add = createPrecompiledContract(altBN128AddAddr, OWNER_ADDRESS);

    SecureRandom random = new SecureRandom();
    byte[] randomInput;
    Pair<Boolean, byte[]> result;
    result = bn128Add.execute(null);
    Assert.assertTrue(result.getLeft());
    result = bn128Add.execute(new byte[0]);
    Assert.assertTrue(result.getLeft());

    for (int i = 5; i < 200; i++) {
      randomInput = new byte[i];
      random.nextBytes(randomInput);
      result = bn128Add.execute(randomInput);
      Assert.assertFalse(result.getLeft());
    }
  }

  @Test
  public void bn128MulRandomTest() {
    PrecompiledContract bn128Mul = createPrecompiledContract(altBN128MulAddr, OWNER_ADDRESS);

    SecureRandom random = new SecureRandom();
    byte[] randomInput;
    Pair<Boolean, byte[]> result;
    result = bn128Mul.execute(null);
    Assert.assertTrue(result.getLeft());
    result = bn128Mul.execute(new byte[0]);
    Assert.assertTrue(result.getLeft());

    for (int i = 5; i < 200; i++) {
      randomInput = new byte[i];
      random.nextBytes(randomInput);
      result = bn128Mul.execute(randomInput);
      Assert.assertFalse(result.getLeft());
    }
  }

  @Test
  public void bn128PairingRandomTest() {
    PrecompiledContract bn128Pairing = createPrecompiledContract(altBN128PairingAddr,
        OWNER_ADDRESS);
    SecureRandom random = new SecureRandom();
    byte[] randomInput;
    Pair<Boolean, byte[]> result;
    result = bn128Pairing.execute(null);
    Assert.assertTrue(result.getLeft());
    result = bn128Pairing.execute(new byte[0]);
    Assert.assertTrue(result.getLeft());

    for (int i = 5; i <= 110 * 192; i++) {
      randomInput = new byte[i];
      random.nextBytes(randomInput);
      result = bn128Pairing.execute(randomInput);
      Assert.assertFalse(result.getLeft());
    }
  }

  @Ignore
  @Test
  public void bn128Bench() throws Exception {
    PrecompiledContract bn128Add = createPrecompiledContract(altBN128AddAddr, OWNER_ADDRESS);
    JSONObject testCase = readJsonFile("bn256Add.json").getJSONObject(0);
    byte[] input = Hex.decode(testCase.getString("Input"));
    bench(bn128Add, input, 10000);

    PrecompiledContract bn128Mul = createPrecompiledContract(altBN128MulAddr, OWNER_ADDRESS);
    testCase = readJsonFile("bn256ScalarMul.json").getJSONObject(1);
    input = Hex.decode(testCase.getString("Input"));
    bench(bn128Mul, input, 1000);

    PrecompiledContract bn128Pairing =
        createPrecompiledContract(altBN128PairingAddr, OWNER_ADDRESS);
    testCase = readJsonFile("bn256Pairing.json").getJSONObject(13);
    input = Hex.decode(testCase.getString("Input"));
    bench(bn128Pairing, input, 100);
  }

  private PrecompiledContract createPrecompiledContract(DataWord addr, String ownerAddress) {
    PrecompiledContract contract = PrecompiledContracts.getContractForAddress(addr);
    contract.setCallerAddress(convertToTronAddress(Hex.decode(ownerAddress)));
    contract.setRepository(RepositoryImpl.createRoot(StoreFactory.getInstance()));
    ProgramResult programResult = new ProgramResult();
    contract.setResult(programResult);
    return contract;
  }

  private JSONArray readJsonFile(String fileName) throws Exception {
    String file1 = SendCoinShieldTest.class.getClassLoader()
        .getResource("json" + File.separator + fileName).getFile();
    List<String> readLines = Files.readLines(new File(file1),
        Charsets.UTF_8);

    return JSONArray
        .parseArray(readLines.stream().reduce((s, s2) -> s + s2).get());
  }

  private static void bench(PrecompiledContract contract, byte[] input, int itersCount) {
    int MATH_WARMUP = 1000;
    for (int i = 0; i < MATH_WARMUP; i++) {
      contract.execute(input);
    }
    long start = System.nanoTime();
    for (int i = 0; i < itersCount; i++) {
      contract.execute(input);
    }
    long end = System.nanoTime();
    logger.info("{} cost {} ns", contract.getClass().getSimpleName(), (end - start) / itersCount);
  }
}
