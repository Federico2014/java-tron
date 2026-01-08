package org.tron.common.runtime.vm;

import static org.junit.Assert.assertArrayEquals;
import static org.tron.core.db.TransactionTrace.convertToTronAddress;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Charsets;
import com.google.common.io.Files;
import java.io.File;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.runtime.ProgramResult;
import org.tron.core.Constant;
import org.tron.core.Wallet;
import org.tron.core.config.args.Args;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.repository.RepositoryImpl;

@Slf4j
public class Secp256R1ContractTest extends BaseTest {

  private static final DataWord secp256R1Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000100");

  private static final String OWNER_ADDRESS;

  static {
    Args.setParam(new String[]{"--output-directory", dbPath(), "--debug"}, Constant.TEST_CONF);
    OWNER_ADDRESS = Wallet.getAddressPreFixString() + "abd4b9367799eaa3197fecb144eb71de1e049abc";
  }

  @Test
  public void secp256R1Test() throws Exception {
    PrecompiledContract secp256R1 = createPrecompiledContract(secp256R1Addr, OWNER_ADDRESS);
    JSONArray testCases = readJsonFile("secp256r1-test-vectors.json");
    for (int i = 0; i < testCases.size(); i++) {
      JSONObject testCase = testCases.getJSONObject(i);
      String name = testCase.getString("Name");
      byte[] input = Hex.decode(testCase.getString("Input"));
      byte[] expected = Hex.decode(testCase.getString("Expected"));
      Pair<Boolean, byte[]> result = secp256R1.execute(input);
      if (result.getLeft()) {
        assertArrayEquals(String.format("Secp256R1 test: %s failed", name), expected,
            result.getRight());
      }
    }
  }

  @Ignore
  @Test
  public void secp256R1Bench() throws Exception {
    PrecompiledContract secp256R1 = createPrecompiledContract(secp256R1Addr, OWNER_ADDRESS);
    JSONObject testCase = readJsonFile("secp256r1-test-vectors.json").getJSONObject(0);
    byte[] input = Hex.decode(testCase.getString("Input"));
    bench(secp256R1, input, 10000);
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
    String file1 = Secp256R1ContractTest.class.getClassLoader()
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
