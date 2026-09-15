package org.tron.common.runtime.vm;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.utils.ByteArray;
import org.tron.core.vm.PrecompiledContracts.BN128Addition;
import org.tron.core.vm.PrecompiledContracts.BN128Multiplication;
import org.tron.core.vm.PrecompiledContracts.BN128Pairing;
import org.tron.core.vm.PrecompiledContracts.Blake2F;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;

/**
 * Consolidated, data-driven regression baseline for the cryptographic precompiles.
 *
 * <p>Each precompile is exercised against a JSON vector file under
 * {@code resources/precompiles/}, following the same {@code {Input, Expected, Gas,
 * Name}} schema already used by {@code p256verify_test_vectors.json}. This keeps the
 * official / computed vectors in one place so they can be reviewed, extended, and
 * reused, rather than being scattered as inline literals across test classes.
 *
 * <p>Vector sources:
 * <ul>
 *   <li>bn128add / bn128mul / bn128pairing — computed against the alt_bn128 curve
 *       using the EIP-197 G2 generator; aligned with go-ethereum's bn256 test data.
 *       Gas values are the Istanbul schedule (EIP-1108).</li>
 *   <li>blake2f — EIP-152 reference vectors (4–7).</li>
 * </ul>
 *
 * <p>An empty {@code Expected} means the precompile is expected to return an empty
 * byte array (failure / no output) without reverting.
 */
public class PrecompileVectorTest {

  public static class TestCase {
    public String Input;
    public String Expected;
    public String Name;
    public long Gas;
  }

  @Before
  public void enableIstanbul() {
    // BN128 Istanbul gas schedule (EIP-1108) is gated behind this flag.
    VMConfig.initAllowTvmIstanbul(1);
  }

  @After
  public void resetIstanbul() {
    VMConfig.initAllowTvmIstanbul(0);
  }

  private static void runVectors(String resource, PrecompiledContract contract)
      throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    List<TestCase> cases;
    try (InputStream is = PrecompileVectorTest.class.getResourceAsStream(resource)) {
      Assert.assertNotNull("vector resource missing: " + resource, is);
      cases = mapper.readerForListOf(TestCase.class).readValue(is);
    }
    Assert.assertFalse("vector list empty: " + resource, cases.isEmpty());

    for (TestCase tc : cases) {
      byte[] input = tc.Input == null || tc.Input.isEmpty()
          ? new byte[0]
          : ByteArray.fromHexString(tc.Input);
      byte[] expected = tc.Expected == null || tc.Expected.isEmpty()
          ? new byte[0]
          : ByteArray.fromHexString(tc.Expected);

      Pair<Boolean, byte[]> result = contract.execute(input);

      Assert.assertTrue(tc.Name + ": precompile must not revert", result.getLeft());
      Assert.assertArrayEquals(tc.Name + ": output mismatch", expected, result.getRight());
      Assert.assertEquals(tc.Name + ": gas mismatch",
          tc.Gas, contract.getEnergyForData(input));
    }
  }

  @Test
  public void bn128AddVectors() throws Exception {
    runVectors("/precompiles/bn128add_test_vectors.json", new BN128Addition());
  }

  @Test
  public void bn128MulVectors() throws Exception {
    runVectors("/precompiles/bn128mul_test_vectors.json", new BN128Multiplication());
  }

  @Test
  public void bn128PairingVectors() throws Exception {
    runVectors("/precompiles/bn128pairing_test_vectors.json", new BN128Pairing());
  }

  @Test
  public void blake2fVectors() throws Exception {
    runVectors("/precompiles/blake2f_test_vectors.json", new Blake2F());
  }
}
