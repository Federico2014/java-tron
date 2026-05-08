package org.tron.common.runtime.vm;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.StringUtil;
import org.tron.common.utils.client.utils.AbiUtil;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.PrecompiledContracts.ValidateMultiSignPQ;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.repository.Repository;
import org.tron.core.vm.repository.RepositoryImpl;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.PQScheme;

/**
 * Unit tests for the 0x17 algorithm-agnostic Permission multi-sign precompile.
 * Mirrors 0x09 hash construction and threshold semantics, while supporting
 * Falcon-512 entries alongside ECDSA against the same Permission.keys[].
 */
@Slf4j
public class ValidateMultiSignPQTest extends BaseTest {

  private static final DataWord ADDR_0X17 = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000017");

  private static final String METHOD_SIGN =
      "validatemultisign(address,uint256,bytes32,bytes[],bytes[],bytes[])";

  private static final byte[] longData;

  static {
    Args.setParam(new String[]{"--output-directory", dbPath(), "--debug"}, TestConstants.TEST_CONF);
    longData = new byte[1000];
    Arrays.fill(longData, (byte) 7);
  }

  private final ValidateMultiSignPQ contract = new ValidateMultiSignPQ();

  @Before
  public void before() {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1);
    dbManager.getDynamicPropertiesStore().saveTotalSignNum(5);
    VMConfig.initAllowFnDsa512(1L);
  }

  @Test
  public void switchOff_returnsNull() {
    VMConfig.initAllowFnDsa512(0L);
    Assert.assertNull(PrecompiledContracts.getContractForAddress(ADDR_0X17));
  }

  @Test
  public void switchOn_returnsContract() {
    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(ADDR_0X17);
    Assert.assertNotNull(pc);
    Assert.assertTrue(pc instanceof ValidateMultiSignPQ);
  }

  @Test
  public void unknownAccount_returnsZero() {
    ECKey owner = new ECKey();
    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(new ECKey().sign(toSign).toByteArray()));
    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList()).getRight());
  }

  @Test
  public void pureEcdsaThresholdReached_returnsOne() {
    ECKey k1 = new ECKey();
    ECKey k2 = new ECKey();
    ECKey owner = new ECKey();
    setupPermission(owner, Arrays.asList(k1.getAddress(), k2.getAddress()),
        Arrays.asList(1, 1), 2, Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = Arrays.asList(
        Hex.toHexString(k1.sign(toSign).toByteArray()),
        Hex.toHexString(k2.sign(toSign).toByteArray()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList()).getRight());
  }

  @Test
  public void purePqThresholdReached_returnsOne() {
    FNDSA pq1 = new FNDSA();
    FNDSA pq2 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] addr1 = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    byte[] addr2 = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq2.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        2, Arrays.asList(addr1, addr2), Arrays.asList(1, 1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(pq1.sign(toSign)),
        Hex.toHexString(pq2.sign(toSign)));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(pq1.getPublicKey()),
        Hex.toHexString(pq2.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void mixedEcdsaAndPq_returnsOne() {
    ECKey k1 = new ECKey();
    FNDSA pq1 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.singletonList(k1.getAddress()), Collections.singletonList(1),
        2, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(pq1.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(pq1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs, pqSigs, pqPks).getRight());
  }

  @Test
  public void pqSignatureForgery_returnsZero() {
    FNDSA pq1 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    byte[] forgedSig = pq1.sign(toSign);
    forgedSig[10] ^= 0x01;

    List<String> pqSigs = Collections.singletonList(Hex.toHexString(forgedSig));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(pq1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void wrongPqPublicKeyLength_returnsZero() {
    FNDSA pq1 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    byte[] truncatedPk = Arrays.copyOf(pq1.getPublicKey(), pq1.getPublicKey().length - 1);

    List<String> pqSigs = Collections.singletonList(Hex.toHexString(pq1.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(truncatedPk));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void mismatchedPqArrayLengths_returnsZero() {
    FNDSA pq1 = new FNDSA();
    FNDSA pq2 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] addr1 = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr1), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(pq1.sign(toSign)),
        Hex.toHexString(pq2.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(pq1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void totalCountOverMaxSize_returnsZero() {
    ECKey owner = new ECKey();
    List<byte[]> ecdsaAddrs = new ArrayList<>();
    List<Integer> ecdsaWeights = new ArrayList<>();
    List<ECKey> ecdsaKeys = new ArrayList<>();
    for (int i = 0; i < 6; i++) {
      ECKey k = new ECKey();
      ecdsaKeys.add(k);
      ecdsaAddrs.add(k.getAddress());
      ecdsaWeights.add(1);
    }
    setupPermission(owner, ecdsaAddrs, ecdsaWeights, 6,
        Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = new ArrayList<>();
    for (ECKey k : ecdsaKeys) {
      ecdsaSigs.add(Hex.toHexString(k.sign(toSign).toByteArray()));
    }

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList()).getRight());
  }

  @Test
  public void duplicatePqSig_doesNotDoubleCount() {
    FNDSA pq1 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        2, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    byte[] sig = pq1.sign(toSign);

    List<String> pqSigs = Arrays.asList(Hex.toHexString(sig), Hex.toHexString(sig));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(pq1.getPublicKey()), Hex.toHexString(pq1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void energyChargesEcdsaAndPqSeparately() {
    FNDSA pq1 = new FNDSA();
    ECKey k1 = new ECKey();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.singletonList(k1.getAddress()), Collections.singletonList(1),
        2, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(pq1.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(pq1.getPublicKey()));

    byte[] input = encodeInput(owner.getAddress(), 2, data, ecdsaSigs, pqSigs, pqPks);
    // 1 ECDSA × 1500 + 1 PQ × 15000 = 16500
    Assert.assertEquals(16500L, contract.getEnergyForData(input));
  }

  @Test
  public void thresholdNotReached_returnsZero() {
    ECKey k1 = new ECKey();
    ECKey k2 = new ECKey();
    ECKey owner = new ECKey();
    setupPermission(owner, Arrays.asList(k1.getAddress(), k2.getAddress()),
        Arrays.asList(1, 1), 2, Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    // Only one valid signature; threshold is 2.
    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList()).getRight());
  }

  @Test
  public void pqKeyNotInPermission_returnsZero() {
    FNDSA inPerm = new FNDSA();
    FNDSA outsider = new FNDSA();
    ECKey owner = new ECKey();
    byte[] inAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, inPerm.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(inAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    // Outsider produces a perfectly valid Falcon signature, but its derived
    // address is not in Permission.keys[] → weight 0 → not counted.
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(outsider.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(outsider.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void pqSigTooLong_returnsZero() {
    FNDSA pq1 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);

    // Pad sig past the 752-byte cap.
    byte[] oversized = new byte[800];
    Arrays.fill(oversized, (byte) 0x42);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(oversized));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(pq1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), pqSigs, pqPks).getRight());
  }

  @Test
  public void bothArraysEmpty_returnsZero() {
    ECKey k1 = new ECKey();
    ECKey owner = new ECKey();
    setupPermission(owner, Collections.singletonList(k1.getAddress()),
        Collections.singletonList(1), 1,
        Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList()).getRight());
  }

  @Test
  public void mixedFailingPqAborts_returnsZero() {
    // Mirrors 0x09 semantics: a verify failure on any submitted entry aborts
    // the whole call with DATA_FALSE — even if other entries would alone meet
    // threshold. Verifies 0x17 does not silently skip a forged PQ signature.
    ECKey k1 = new ECKey();
    ECKey k2 = new ECKey();
    FNDSA pq1 = new FNDSA();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    setupPermission(owner,
        Arrays.asList(k1.getAddress(), k2.getAddress()), Arrays.asList(1, 1),
        2, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> ecdsaSigs = Arrays.asList(
        Hex.toHexString(k1.sign(toSign).toByteArray()),
        Hex.toHexString(k2.sign(toSign).toByteArray()));
    byte[] forged = pq1.sign(toSign);
    forged[0] ^= 0x55;
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(forged));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(pq1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs, pqSigs, pqPks).getRight());
  }

  // -------- helpers --------

  private void setupPermission(ECKey owner,
                               List<byte[]> ecdsaKeyAddrs, List<Integer> ecdsaWeights,
                               int threshold,
                               List<byte[]> pqKeyAddrs, List<Integer> pqWeights) {
    AccountCapsule account = new AccountCapsule(ByteString.copyFrom(owner.getAddress()),
        Protocol.AccountType.Normal, System.currentTimeMillis(), true,
        dbManager.getDynamicPropertiesStore());

    Protocol.Permission.Builder perm = Protocol.Permission.newBuilder()
        .setType(Protocol.Permission.PermissionType.Active)
        .setId(2)
        .setPermissionName("active")
        .setThreshold(threshold)
        .setOperations(ByteString.copyFrom(ByteArray.fromHexString(
            "0000000000000000000000000000000000000000000000000000000000000000")));
    for (int i = 0; i < ecdsaKeyAddrs.size(); i++) {
      perm.addKeys(Protocol.Key.newBuilder()
          .setAddress(ByteString.copyFrom(ecdsaKeyAddrs.get(i)))
          .setWeight(ecdsaWeights.get(i)).build());
    }
    for (int i = 0; i < pqKeyAddrs.size(); i++) {
      perm.addKeys(Protocol.Key.newBuilder()
          .setAddress(ByteString.copyFrom(pqKeyAddrs.get(i)))
          .setWeight(pqWeights.get(i)).build());
    }
    account.updatePermissions(account.getPermissionById(0), null,
        Collections.singletonList(perm.build()));
    dbManager.getAccountStore().put(owner.getAddress(), account);
  }

  private byte[] computeHash(byte[] address, int permissionId, byte[] data) {
    byte[] combined = ByteUtil.merge(address, ByteArray.fromInt(permissionId), data);
    return Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), combined);
  }

  private byte[] encodeInput(byte[] ownerAddr, int permissionId, byte[] data,
                             List<String> ecdsaSigs, List<String> pqSigs, List<String> pqPks) {
    List<Object> parameters = Arrays.asList(
        StringUtil.encode58Check(ownerAddr),
        permissionId,
        "0x" + Hex.toHexString(data),
        toHexList(ecdsaSigs),
        toHexList(pqSigs),
        toHexList(pqPks));
    return Hex.decode(AbiUtil.parseParameters(METHOD_SIGN, parameters));
  }

  private Pair<Boolean, byte[]> runContract(byte[] ownerAddr, int permissionId, byte[] data,
                                            List<String> ecdsaSigs, List<String> pqSigs,
                                            List<String> pqPks) {
    byte[] input = encodeInput(ownerAddr, permissionId, data, ecdsaSigs, pqSigs, pqPks);
    Repository deposit = RepositoryImpl.createRoot(StoreFactory.getInstance());
    contract.setRepository(deposit);
    Pair<Boolean, byte[]> ret = contract.execute(input);
    logger.info("0x17 result: {}", Hex.toHexString(ret.getRight()));
    return ret;
  }

  private static List<Object> toHexList(List<String> hexes) {
    List<Object> out = new ArrayList<>(hexes.size());
    for (String h : hexes) {
      out.add(h.startsWith("0x") ? h : ("0x" + h));
    }
    return out;
  }
}
