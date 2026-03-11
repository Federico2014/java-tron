package org.tron.common.runtime.vm;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.tron.core.db.TransactionTrace.convertToTronAddress;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Charsets;
import com.google.common.io.Files;
import java.io.File;
import java.security.SecureRandom;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.besu.nativelib.gnark.LibGnarkEIP196;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.tron.core.vm.config.VMConfig;
import org.tron.common.BaseTest;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
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
    Args.setParam(new String[]{"--output-directory", dbPath(), "--debug"}, "config-test.conf");
    OWNER_ADDRESS = Wallet.getAddressPreFixString() + "abd4b9367799eaa3197fecb144eb71de1e049abc";
  }

  @Before
  public void setUp() {
    VMConfig.initAllowOptimizedBn128(1);
  }

  @After
  public void tearDown() {
    VMConfig.initAllowOptimizedBn128(0);
  }

  @Test
  public void testLibraryLoading() {
    assertTrue("Native LibGnarkEIP196 library should be loaded", LibGnarkEIP196.ENABLED);
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

    assertTrue(result.getLeft());
    Assert.assertArrayEquals(ByteArray.fromHexString(
        "0x0000000000000000000000000000000000000000000000000000000000000001"), result.getRight());

    intput = inValidPointsOutsideSubgroupG2();
    result = bn128Pairing.execute(intput);
    Assert.assertFalse(result.getLeft());
    Assert.assertEquals(0, result.getRight().length);
  }

  @Test
  public void bn128AdditionRandomTest() {
    PrecompiledContract bn128Add = createPrecompiledContract(altBN128AddAddr, OWNER_ADDRESS);

    SecureRandom random = new SecureRandom();
    byte[] randomInput;
    Pair<Boolean, byte[]> result;
    result = bn128Add.execute(null);
    assertTrue(result.getLeft());
    result = bn128Add.execute(new byte[0]);
    assertTrue(result.getLeft());

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
    assertTrue(result.getLeft());
    result = bn128Mul.execute(new byte[0]);
    assertTrue(result.getLeft());

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
    assertTrue(result.getLeft());
    result = bn128Pairing.execute(new byte[0]);
    assertTrue(result.getLeft());

    for (int i = 5; i <= 110 * 192; i++) {
      randomInput = new byte[i];
      random.nextBytes(randomInput);
      result = bn128Pairing.execute(randomInput);
      Assert.assertFalse(result.getLeft());
    }
  }

  @Ignore
  @Test
  public void bn128BenchOptimized() throws Exception {
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

  @Ignore
  @Test
  public void bn128BenchUnoptimized() throws Exception {
    VMConfig.initAllowOptimizedBn128(0);
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
    VMConfig.initAllowOptimizedBn128(1);
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
    int BENCH_WARMUP = 1000;
    for (int i = 0; i < BENCH_WARMUP; i++) {
      contract.execute(input);
    }
    long start = System.nanoTime();
    for (int i = 0; i < itersCount; i++) {
      contract.execute(input);
    }
    long end = System.nanoTime();
    // Convert nanoseconds to milliseconds
    double avgMs = ((double) (end - start)) / itersCount / 1_000_000.0;
    logger.info("{} execution time: {} ms/op average over {} iterations",
        contract.getClass().getSimpleName(), String.format("%.3f", avgMs), itersCount);
  }

  @Ignore
  @Test
  public void bn128PairingMaxPairsTest() {
    PrecompiledContract bn128Pairing = createPrecompiledContract(altBN128PairingAddr,
        OWNER_ADDRESS);

    byte[] twoValidPairs = validPointsByte(); // length is 192 * 2 = 384

    // Construct 100 pairs (50 * 2 pairs)
    byte[] hundredPairs = new byte[192 * 100];
    for (int i = 0; i < 50; i++) {
      System.arraycopy(twoValidPairs, 0, hundredPairs, i * 384, 384);
    }

    // Default tearDown sets VMConfig.allowOptimizedBn128 back to 0, but setup sets it to 1.
    // 1. In optimized mode, test that exactly 100 pairs execute successfully
    Pair<Boolean, byte[]> result = bn128Pairing.execute(hundredPairs);
    assertTrue("100 pairs passed optimized verification", result.getLeft());
    Assert.assertArrayEquals(ByteArray.fromHexString(
        "0x0000000000000000000000000000000000000000000000000000000000000001"),
        result.getRight());

    // 2. In optimized mode, test that 102 pairs will be rejected securely
    byte[] hundredTwoPairs = new byte[192 * 102];
    System.arraycopy(hundredPairs, 0, hundredTwoPairs, 0, 192 * 100);
    System.arraycopy(twoValidPairs, 0, hundredTwoPairs, 192 * 100, 384);
    result = bn128Pairing.execute(hundredTwoPairs);
    Assert.assertFalse("102 pairs should be rejected in optimized mode", result.getLeft());
    Assert.assertEquals(0, result.getRight().length);

    // 3. Fallback/Unoptimized mode does not have the max size constraint
    VMConfig.initAllowOptimizedBn128(0);
    result = bn128Pairing.execute(hundredTwoPairs);
    assertTrue("102 pairs should pass in unoptimized mode", result.getLeft());
    Assert.assertArrayEquals(ByteArray.fromHexString(
        "0x0000000000000000000000000000000000000000000000000000000000000001"),
        result.getRight());

    VMConfig.initAllowOptimizedBn128(1);
  }

  @Test
  public void bn128Pairing100PairsBenchTest() {
    PrecompiledContract bn128Pairing = createPrecompiledContract(altBN128PairingAddr,
        OWNER_ADDRESS);

    byte[] twoValidPairs = validPointsByte();
    byte[] hundredPairs = new byte[192 * 100];
    for (int i = 0; i < 50; i++) {
      System.arraycopy(twoValidPairs, 0, hundredPairs, i * 384, 384);
    }

    // Warmup
    for (int i = 0; i < 5; i++) {
      bn128Pairing.execute(hundredPairs);
    }

    int iters = 50;
    long start = System.nanoTime();
    for (int i = 0; i < iters; i++) {
      bn128Pairing.execute(hundredPairs);
    }
    long end = System.nanoTime();

    double avgMs = (end - start) / 1_000_000.0 / iters;
    logger.info("BN128 Pairing (100 pairs) optimized execution time: {} ms/op "
            + "average over {} iterations", String.format("%.2f", avgMs), iters);

    // Unoptimized
    VMConfig.initAllowOptimizedBn128(0);
    start = System.nanoTime();
    for (int i = 0; i < iters; i++) {
      bn128Pairing.execute(hundredPairs);
    }
    end = System.nanoTime();
    double unoptimizedMs = (end - start) / 1_000_000.0 / iters;
    logger.info("BN128 Pairing (100 pairs) Unoptimized execution time: {} ms/op",
        String.format("%.2f", unoptimizedMs));

    // Restore optimization setting
    VMConfig.initAllowOptimizedBn128(1);
  }
}
