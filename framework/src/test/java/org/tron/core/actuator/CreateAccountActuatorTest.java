package org.tron.core.actuator;

import static org.junit.Assert.fail;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.pqc.FNDSA;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.MLDSA65;
import org.tron.common.crypto.pqc.PQSignatureRegistry;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.StringUtil;
import org.tron.core.Wallet;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ContractExeException;
import org.tron.core.exception.ContractValidateException;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.PQPublicKey;
import org.tron.protos.Protocol.SignatureScheme;
import org.tron.protos.Protocol.Transaction.Result.code;
import org.tron.protos.contract.AccountContract.AccountCreateContract;
import org.tron.protos.contract.AssetIssueContractOuterClass;

@Slf4j
public class CreateAccountActuatorTest extends BaseTest {

  private static final String OWNER_ADDRESS_FIRST;
  private static final String ACCOUNT_NAME_SECOND = "ownerS";
  private static final String OWNER_ADDRESS_SECOND;
  private static final String INVALID_ACCOUNT_ADDRESS;

  static {
    Args.setParam(new String[]{"--output-directory", dbPath()}, TestConstants.TEST_CONF);
    OWNER_ADDRESS_FIRST =
        Wallet.getAddressPreFixString() + "abd4b9367799eaa3197fecb144eb71de1e049abc";
    OWNER_ADDRESS_SECOND =
        Wallet.getAddressPreFixString() + "548794500882809695a8a687866e76d4271a1abc";
    INVALID_ACCOUNT_ADDRESS = Wallet.getAddressPreFixString() + "12344500882809695a8a687866";
  }

  /**
   * create temp Capsule test need.
   */
  @Before
  public void createCapsule() {
    AccountCapsule ownerCapsule =
        new AccountCapsule(
            ByteString.copyFrom(ByteArray.fromHexString(OWNER_ADDRESS_SECOND)),
            ByteString.copyFromUtf8(ACCOUNT_NAME_SECOND),
            AccountType.AssetIssue);
    dbManager.getAccountStore().put(ownerCapsule.getAddress().toByteArray(), ownerCapsule);
    dbManager.getAccountStore().delete(ByteArray.fromHexString(OWNER_ADDRESS_FIRST));
  }

  private Any getContract(String ownerAddress, String accountAddress) {
    return Any.pack(
        AccountCreateContract.newBuilder()
            .setAccountAddress(ByteString.copyFrom(ByteArray.fromHexString(accountAddress)))
            .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(ownerAddress)))
            .build());
  }

  /**
   * Unit test.
   */
  @Test
  public void firstCreateAccount() {
    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(getContract(OWNER_ADDRESS_SECOND, OWNER_ADDRESS_FIRST));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    try {
      actuator.validate();
      actuator.execute(ret);
      Assert.assertEquals(ret.getInstance().getRet(), code.SUCESS);
      AccountCapsule accountCapsule =
          dbManager.getAccountStore().get(ByteArray.fromHexString(OWNER_ADDRESS_FIRST));
      Assert.assertNotNull(accountCapsule);
      Assert.assertEquals(
          StringUtil.createReadableString(accountCapsule.getAddress()),
          OWNER_ADDRESS_FIRST);
    } catch (ContractValidateException e) {
      logger.info(e.getMessage());
      Assert.assertFalse(e instanceof ContractValidateException);
    } catch (ContractExeException e) {
      Assert.assertFalse(e instanceof ContractExeException);
    }
  }

  /**
   * Unit test.
   */
  @Test
  public void secondCreateAccount() {
    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(getContract(OWNER_ADDRESS_SECOND, OWNER_ADDRESS_SECOND));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    try {
      actuator.validate();
      actuator.execute(ret);
    } catch (ContractValidateException e) {
      Assert.assertTrue(e instanceof ContractValidateException);
      Assert.assertEquals("Account has existed", e.getMessage());
      AccountCapsule accountCapsule =
          dbManager.getAccountStore().get(ByteArray.fromHexString(OWNER_ADDRESS_SECOND));
      Assert.assertNotNull(accountCapsule);
      Assert.assertEquals(
          accountCapsule.getAddress(),
          ByteString.copyFrom(ByteArray.fromHexString(OWNER_ADDRESS_SECOND)));
    } catch (ContractExeException e) {
      Assert.assertFalse(e instanceof ContractExeException);
    }
  }

  /**
   * create a account will take some fee, which change account balance after creatation
   */
  @Test
  public void balanceAfterCreate() {
    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(getContract(OWNER_ADDRESS_SECOND, OWNER_ADDRESS_FIRST));
    TransactionResultCapsule ret = new TransactionResultCapsule();

    long currentBalance = dbManager.getAccountStore()
        .get(ByteArray.fromHexString(OWNER_ADDRESS_SECOND)).getBalance();
    long blackholeBalance = dbManager.getAccountStore().getBlackhole().getBalance();

    try {
      actuator.validate();
      actuator.execute(ret);
      Assert.assertEquals(ret.getInstance().getRet(), code.SUCESS);
      Assert.assertEquals(currentBalance, dbManager.getAccountStore()
          .get(ByteArray.fromHexString(OWNER_ADDRESS_SECOND)).getBalance() - actuator.calcFee());
      Assert.assertEquals(blackholeBalance, dbManager.getAccountStore()
          .getBlackhole().getBalance() + actuator.calcFee());

    } catch (ContractValidateException e) {
      logger.info(e.getMessage());
      Assert.assertFalse(e instanceof ContractValidateException);
    } catch (ContractExeException e) {
      Assert.assertFalse(e instanceof ContractExeException);
    }
  }


  /**
   * owner address not exit in DB
   */
  @Test
  public void noExitsAccount() {
    CreateAccountActuator actuator = new CreateAccountActuator();
    TransactionResultCapsule ret = new TransactionResultCapsule();

    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(getContract(OWNER_ADDRESS_SECOND, OWNER_ADDRESS_FIRST));
    byte[] ownerAddress = ByteArray.fromHexString(OWNER_ADDRESS_SECOND);
    String readableOwnerAddress = StringUtil.createReadableString(ownerAddress);
    // delete account address, which just create
    dbManager.getAccountStore().delete(ByteArray.fromHexString(OWNER_ADDRESS_SECOND));

    processAndCheckInvalid(actuator, ret, "Account[",
        "Account[" + readableOwnerAddress + "] not exists");
  }

  /**
   * not have enough fee to create a account
   */
  @Test
  public void inSufficientFeeAccount() {
    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(getContract(OWNER_ADDRESS_SECOND, OWNER_ADDRESS_FIRST));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    AccountCapsule owner = dbManager.getAccountStore()
        .get(ByteArray.fromHexString(OWNER_ADDRESS_SECOND));
    owner.setBalance(-100);
    dbManager.getAccountStore().put(owner.createDbKey(), owner);

    processAndCheckInvalid(actuator, ret, "Validate CreateAccountActuator error, insufficient fee.",
        "Validate CreateAccountActuator error, insufficient fee.");
  }

  /**
   * Invalid account address
   */
  @Test
  public void invalidAccount() {
    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(getContract(OWNER_ADDRESS_SECOND, INVALID_ACCOUNT_ADDRESS));
    TransactionResultCapsule ret = new TransactionResultCapsule();

    processAndCheckInvalid(actuator, ret, "Invalid account address", "Invalid account address");
  }


  @Test
  public void commonErrorCheck() {

    CreateAccountActuator actuator = new CreateAccountActuator();
    ActuatorTest actuatorTest = new ActuatorTest(actuator, dbManager);
    actuatorTest.noContract();

    Any invalidContractTypes = Any.pack(AssetIssueContractOuterClass.AssetIssueContract.newBuilder()
        .build());
    actuatorTest.setInvalidContract(invalidContractTypes);
    actuatorTest.setInvalidContractTypeMsg("contract type error",
        "contract type error,expected type [AccountCreateContract],real type[");
    actuatorTest.invalidContractType();

    actuatorTest.setContract(getContract(OWNER_ADDRESS_SECOND, OWNER_ADDRESS_FIRST));
    actuatorTest.nullTransationResult();

    actuatorTest.setNullDBManagerMsg("No account store or contract store!");
    actuatorTest.nullDBManger();

  }

  private static byte[] filledSeed(int value, int length) {
    byte[] seed = new byte[length];
    Arrays.fill(seed, (byte) value);
    return seed;
  }

  private Any pqContract(String ownerAddress, byte[] accountAddress,
      SignatureScheme scheme, byte[] pqPublicKey) {
    return Any.pack(
        AccountCreateContract.newBuilder()
            .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(ownerAddress)))
            .setAccountAddress(ByteString.copyFrom(accountAddress))
            .setPqKey(PQPublicKey.newBuilder()
                .setScheme(scheme)
                .setPublicKey(ByteString.copyFrom(pqPublicKey))
                .build())
            .build());
  }

  private void runPqHappyPath(SignatureScheme scheme, byte[] pqPublicKey) {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    if (scheme == SignatureScheme.FN_DSA) {
      dbManager.getDynamicPropertiesStore().saveAllowFnDsa(1L);
    } else {
      dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    }
    byte[] derivedAddress = PQSignatureRegistry.computeAddress(scheme, pqPublicKey);
    dbManager.getAccountStore().delete(derivedAddress);

    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(pqContract(OWNER_ADDRESS_SECOND, derivedAddress, scheme, pqPublicKey));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    try {
      actuator.validate();
      actuator.execute(ret);
      Assert.assertEquals(code.SUCESS, ret.getInstance().getRet());

      AccountCapsule created = dbManager.getAccountStore().get(derivedAddress);
      Assert.assertNotNull(created);
      // Owner permission bound to PQ key, address field empty.
      Assert.assertEquals(1, created.getInstance().getOwnerPermission().getKeysCount());
      Assert.assertEquals(ByteString.EMPTY,
          created.getInstance().getOwnerPermission().getKeys(0).getAddress());
      Assert.assertEquals(scheme,
          created.getInstance().getOwnerPermission().getKeys(0).getPqKey().getScheme());
      Assert.assertEquals(ByteString.copyFrom(pqPublicKey),
          created.getInstance().getOwnerPermission().getKeys(0).getPqKey().getPublicKey());
      // Active permission bound to same PQ key.
      Assert.assertEquals(1, created.getInstance().getActivePermissionCount());
      Assert.assertEquals(scheme,
          created.getInstance().getActivePermission(0).getKeys(0).getPqKey().getScheme());
    } catch (ContractValidateException | ContractExeException e) {
      logger.info(e.getMessage());
      Assert.fail(e.getMessage());
    }
  }

  @Test
  public void createPqAccount_mlDsa44_success() {
    MLDSA44 kp = new MLDSA44(filledSeed(0x11, MLDSA44.SEED_LENGTH));
    runPqHappyPath(SignatureScheme.ML_DSA_44, kp.getPublicKey());
  }

  @Test
  public void createPqAccount_mlDsa65_success() {
    MLDSA65 kp = new MLDSA65(filledSeed(0x12, MLDSA65.SEED_LENGTH));
    runPqHappyPath(SignatureScheme.ML_DSA_65, kp.getPublicKey());
  }

  @Test
  public void createPqAccount_fnDsa_success() {
    FNDSA kp = new FNDSA(filledSeed(0x13, FNDSA.SEED_LENGTH));
    runPqHappyPath(SignatureScheme.FN_DSA, kp.getPublicKey());
  }

  @Test
  public void createPqAccount_addressMismatch() {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    MLDSA44 kp = new MLDSA44(filledSeed(0x21, MLDSA44.SEED_LENGTH));
    byte[] wrongAddress = ByteArray.fromHexString(OWNER_ADDRESS_FIRST);

    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(pqContract(OWNER_ADDRESS_SECOND, wrongAddress,
            SignatureScheme.ML_DSA_44, kp.getPublicKey()));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    processAndCheckInvalid(actuator, ret,
        "account_address does not match the address derived from pq_key",
        "account_address does not match the address derived from pq_key");
  }

  @Test
  public void createPqAccount_wrongPubKeyLength() {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    byte[] truncated = new byte[MLDSA44.PUBLIC_KEY_LENGTH - 1];
    byte[] derivedAddress = ByteArray.fromHexString(OWNER_ADDRESS_FIRST);

    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(pqContract(OWNER_ADDRESS_SECOND, derivedAddress,
            SignatureScheme.ML_DSA_44, truncated));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    processAndCheckInvalid(actuator, ret,
        "Invalid PQ public key length for scheme ML_DSA_44",
        "Invalid PQ public key length for scheme ML_DSA_44");
  }

  @Test
  public void createPqAccount_schemeNotActivated() {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(0L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa(0L);
    MLDSA44 kp = new MLDSA44(filledSeed(0x31, MLDSA44.SEED_LENGTH));
    byte[] derivedAddress = PQSignatureRegistry.computeAddress(
        SignatureScheme.ML_DSA_44, kp.getPublicKey());
    dbManager.getAccountStore().delete(derivedAddress);

    CreateAccountActuator actuator = new CreateAccountActuator();
    actuator.setChainBaseManager(dbManager.getChainBaseManager())
        .setAny(pqContract(OWNER_ADDRESS_SECOND, derivedAddress,
            SignatureScheme.ML_DSA_44, kp.getPublicKey()));
    TransactionResultCapsule ret = new TransactionResultCapsule();
    processAndCheckInvalid(actuator, ret,
        "PQ scheme not activated: ML_DSA_44",
        "PQ scheme not activated: ML_DSA_44");
  }

  private void processAndCheckInvalid(CreateAccountActuator actuator, TransactionResultCapsule ret,
      String failMsg,
      String expectedMsg) {
    try {
      actuator.validate();
      actuator.execute(ret);

      fail(failMsg);
    } catch (ContractValidateException e) {
      Assert.assertTrue(e instanceof ContractValidateException);
      Assert.assertEquals(expectedMsg, e.getMessage());
    } catch (ContractExeException e) {
      Assert.assertFalse(e instanceof ContractExeException);
    } catch (RuntimeException e) {
      Assert.assertTrue(e instanceof RuntimeException);
      Assert.assertEquals(expectedMsg, e.getMessage());
    }
  }


}
