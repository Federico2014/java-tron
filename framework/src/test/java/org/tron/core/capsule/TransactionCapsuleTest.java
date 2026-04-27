package org.tron.core.capsule;

import static org.tron.protos.Protocol.Transaction.Result.contractResult.BAD_JUMP_DESTINATION;
import static org.tron.protos.Protocol.Transaction.Result.contractResult.PRECOMPILED_CONTRACT;
import static org.tron.protos.Protocol.Transaction.Result.contractResult.SUCCESS;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.MLDSA65;
import org.tron.common.crypto.pqc.SLHDSA;
import org.tron.common.crypto.pqc.PqAuthDigest;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.StringUtil;
import org.tron.core.Wallet;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.AuthWitness;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;
import org.tron.protos.Protocol.SignatureScheme;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.Protocol.Transaction.Result;
import org.tron.protos.Protocol.Transaction.Result.contractResult;
import org.tron.protos.Protocol.Transaction.raw;
import org.tron.protos.contract.BalanceContract.TransferContract;
import org.tron.protos.contract.SmartContractOuterClass.TriggerSmartContract;

@Slf4j
public class TransactionCapsuleTest extends BaseTest {

  private static String OWNER_ADDRESS;

  @BeforeClass
  public static void init() {
    Args.setParam(new String[]{"-d", dbPath()}, TestConstants.TEST_CONF);
    OWNER_ADDRESS = Wallet.getAddressPreFixString() + "03702350064AD5C1A8AA6B4D74B051199CFF8EA7";
  }

  /**
   * create temp Capsule test need.
   */
  @Before
  public void createAccountCapsule() {
    AccountCapsule ownerCapsule = new AccountCapsule(ByteString.copyFromUtf8("owner"),
        StringUtil.hexString2ByteString(OWNER_ADDRESS), AccountType.Normal, 10_000_000_000L);
    dbManager.getAccountStore().put(ownerCapsule.createDbKey(), ownerCapsule);
  }

  @Test
  public void trxCapsuleClearTest() {
    Transaction tx = Transaction.newBuilder()
        .addRet(Result.newBuilder().setContractRet(contractResult.OUT_OF_TIME).build()).build();
    TransactionCapsule trxCap = new TransactionCapsule(tx);
    Result.contractResult contractResult = trxCap.getContractResult();
    trxCap.resetResult();
    Assert.assertEquals(trxCap.getInstance().getRetCount(), 0);
    trxCap.setResultCode(contractResult);
    Assert.assertEquals(trxCap.getInstance()
        .getRet(0).getContractRet(), Result.contractResult.OUT_OF_TIME);
  }

  @Test
  public void testRemoveRedundantRet() {
    Transaction.Builder transaction = Transaction.newBuilder().setRawData(raw.newBuilder()
        .addContract(Transaction.Contract.newBuilder().setType(ContractType.TriggerSmartContract))
        .setFeeLimit(1000000000)).build().toBuilder();
    transaction.addRet(Result.newBuilder().setContractRet(SUCCESS).build());
    transaction.addRet(Result.newBuilder().setContractRet(PRECOMPILED_CONTRACT).build());
    transaction.addRet(Result.newBuilder().setContractRet(BAD_JUMP_DESTINATION).build());
    TransactionCapsule transactionCapsule = new TransactionCapsule(transaction.build());
    transactionCapsule.removeRedundantRet();
    Assert.assertEquals(1, transactionCapsule.getInstance().getRetCount());
    Assert.assertEquals(SUCCESS, transactionCapsule.getInstance().getRet(0).getContractRet());
  }

  // --------------------- ML-DSA auth_witness verification ---------------------

  private static final String PQ_OWNER_HEX =
      "41abd4b9367799eaa3197fecb144eb71de1e049abc";
  private static final String PQ_SIGNER_HEX =
      "41548794500882809695a8a687866e76d4271a1abc";

  private byte[] sign(MLDSA44 kp, byte[] msg) {
    return MLDSA44.sign(kp.getPrivateKey(), msg);
  }

  private Transaction buildTransferTx(String ownerHex, int permissionId) {
    TransferContract transfer = TransferContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(ownerHex)))
        .setToAddress(ByteString.copyFrom(ByteArray.fromHexString(PQ_SIGNER_HEX)))
        .setAmount(1L)
        .build();
    Transaction.Contract c = Transaction.Contract.newBuilder()
        .setType(ContractType.TransferContract)
        .setParameter(Any.pack(transfer))
        .setPermissionId(permissionId)
        .build();
    raw rawData = raw.newBuilder().addContract(c).build();
    return Transaction.newBuilder().setRawData(rawData).build();
  }

  private void putAccountWithPqPermission(
      String ownerHex, byte[] pqPublicKey, SignatureScheme scheme) {
    byte[] addr = ByteArray.fromHexString(ownerHex);
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    Key pqKey = Key.newBuilder()
        .setAddress(ByteString.copyFrom(signerAddr))
        .setWeight(1L)
        .setScheme(scheme)
        .setPublicKey(ByteString.copyFrom(pqPublicKey))
        .build();
    Permission owner = Permission.newBuilder()
        .setType(PermissionType.Owner)
        .setPermissionName("owner")
        .setThreshold(1)
        .addKeys(pqKey)
        .build();
    AccountCapsule acc = new AccountCapsule(ByteString.copyFrom(addr),
        ByteString.copyFromUtf8("pqowner"), AccountType.Normal);
    acc.updatePermissions(owner, null, java.util.Collections.emptyList());
    dbManager.getAccountStore().put(addr, acc);
  }

  @Test
  public void authWitnessBeforeActivationRejected() {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(0L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa65(0L);
    dbManager.getDynamicPropertiesStore().saveAllowSlhDsa(0L);
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0).toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(ByteArray.fromHexString(PQ_SIGNER_HEX)))
            .setSignature(ByteString.copyFrom(new byte[2420]))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(tx);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("should reject auth_witness before activation");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("no PQ scheme is activated"));
    }
  }

  @Test
  public void signatureAndAuthWitnessAreMutuallyExclusive() {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0).toBuilder()
        .addSignature(ByteString.copyFrom(new byte[65]))
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(ByteArray.fromHexString(PQ_SIGNER_HEX)))
            .setSignature(ByteString.copyFrom(new byte[2420]))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(tx);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("should reject when both signature and auth_witness present");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("mutually exclusive"));
    }
  }

  @Test
  public void validAuthWitnessAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    MLDSA44 kp = new MLDSA44();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.ML_DSA_44);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = sign(kp, digest);

    Transaction signed = tx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    Assert.assertTrue(cap.validatePubSignature(dbManager.getAccountStore(),
        dbManager.getDynamicPropertiesStore()));
  }

  @Test
  public void duplicateSignerRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    MLDSA44 kp = new MLDSA44();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.ML_DSA_44);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = sign(kp, digest);
    AuthWitness aw = AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(signerAddr))
        .setSignature(ByteString.copyFrom(sig))
        .build();
    Transaction signed = tx.toBuilder().addAuthWitness(aw).addAuthWitness(aw).build();

    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("duplicate signer should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("duplicate signer"));
    }
  }

  @Test
  public void tamperedAuthWitnessRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    MLDSA44 kp = new MLDSA44();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.ML_DSA_44);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = sign(kp, digest);
    sig[0] ^= 0x01;

    Transaction signed = tx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("tampered signature should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("pq sig invalid"));
    }
  }

  @Test
  public void signerNotInPermissionRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    MLDSA44 kp = new MLDSA44();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.ML_DSA_44);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] otherSigner = ByteArray.fromHexString(
        "41BCE23C7D683B889326F762DDA2223A861EDA2E5C");
    byte[] digest = PqAuthDigest.tx(txid, 0, otherSigner);
    byte[] sig = sign(kp, digest);

    Transaction signed = tx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(otherSigner))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("unknown signer should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("not in permission"));
    }
  }

  /**
   * TRC20 transfer(address,uint256) call data: 4-byte selector + 32-byte address + 32-byte amount.
   */
  private Transaction buildTrc20TransferTx(String ownerHex, int permissionId) {
    // transfer(address,uint256) selector
    byte[] selector = ByteArray.fromHexString("a9059cbb");
    byte[] toAddrPadded = new byte[32];
    byte[] toRaw = ByteArray.fromHexString(PQ_SIGNER_HEX.substring(2)); // strip "41"
    System.arraycopy(toRaw, 0, toAddrPadded, 12, 20);
    byte[] amountPadded = new byte[32];
    amountPadded[31] = (byte) 100; // 100 tokens
    byte[] callData = new byte[selector.length + toAddrPadded.length + amountPadded.length];
    System.arraycopy(selector, 0, callData, 0, 4);
    System.arraycopy(toAddrPadded, 0, callData, 4, 32);
    System.arraycopy(amountPadded, 0, callData, 36, 32);

    byte[] contractAddr = ByteArray.fromHexString("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
    TriggerSmartContract trigger = TriggerSmartContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(ownerHex)))
        .setContractAddress(ByteString.copyFrom(contractAddr))
        .setData(ByteString.copyFrom(callData))
        .build();
    Transaction.Contract c = Transaction.Contract.newBuilder()
        .setType(ContractType.TriggerSmartContract)
        .setParameter(Any.pack(trigger))
        .setPermissionId(permissionId)
        .build();
    raw rawData = raw.newBuilder()
        .addContract(c)
        .setFeeLimit(150_000_000L)
        .build();
    return Transaction.newBuilder().setRawData(rawData).build();
  }

  /** Returns [serializedSize, packSize, maxTxPerBlock] for ECKey, ML-DSA-44, ML-DSA-65. */
  private long[][] measureSizes(Transaction baseTx) {
    final long blockLimit = 2_000_000L;
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);

    // ECKey (ECDSA): 65-byte signature in `signature` field
    ECKey ecKey = new ECKey();
    TransactionCapsule ecCap = new TransactionCapsule(baseTx);
    ecCap.sign(ecKey.getPrivKeyBytes());
    long ecSerial = ecCap.getInstance().toByteArray().length;
    long ecPack = ecCap.computeTrxSizeForBlockMessage();

    // ML-DSA-44: 2420-byte signature in auth_witness
    MLDSA44 kp44 = new MLDSA44();
    byte[] txid44 = Sha256Hash.of(true, baseTx.getRawData().toByteArray()).getBytes();
    byte[] sig44 = MLDSA44.sign(kp44.getPrivateKey(), PqAuthDigest.tx(txid44, 0, signerAddr));
    Transaction tx44 = baseTx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig44))
            .build())
        .build();
    TransactionCapsule cap44 = new TransactionCapsule(tx44);
    long d44Serial = tx44.toByteArray().length;
    long d44Pack = cap44.computeTrxSizeForBlockMessage();

    // ML-DSA-65: 3309-byte signature in auth_witness
    MLDSA65 kp65 = new MLDSA65();
    byte[] txid65 = Sha256Hash.of(true, baseTx.getRawData().toByteArray()).getBytes();
    byte[] sig65 = MLDSA65.sign(kp65.getPrivateKey(), PqAuthDigest.tx(txid65, 0, signerAddr));
    Transaction tx65 = baseTx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig65))
            .build())
        .build();
    TransactionCapsule cap65 = new TransactionCapsule(tx65);
    long d65Serial = tx65.toByteArray().length;
    long d65Pack = cap65.computeTrxSizeForBlockMessage();

    return new long[][]{
        {ecSerial,  ecPack,  blockLimit / ecPack},
        {d44Serial, d44Pack, blockLimit / d44Pack},
        {d65Serial, d65Pack, blockLimit / d65Pack}
    };
  }

  @Test
  public void transactionSizeComparisonByScheme() {
    long[][] trx   = measureSizes(buildTransferTx(PQ_OWNER_HEX, 0));
    long[][] trc20 = measureSizes(buildTrc20TransferTx(PQ_OWNER_HEX, 0));

    String[] labels = {"ECKey (ECDSA)", "ML-DSA-44", "ML-DSA-65"};
    System.out.println("=== TRX transfer ===");
    for (int i = 0; i < 3; i++) {
      System.out.printf("  %s: serial=%d B  pack=%d B  maxTx/block=%d%n",
          labels[i], trx[i][0], trx[i][1], trx[i][2]);
    }
    System.out.println("=== TRC20 transfer ===");
    for (int i = 0; i < 3; i++) {
      System.out.printf("  %s: serial=%d B  pack=%d B  maxTx/block=%d%n",
          labels[i], trc20[i][0], trc20[i][1], trc20[i][2]);
    }

    for (int i = 0; i < 2; i++) {
      Assert.assertTrue(trx[i + 1][0]   > trx[i][0]);
      Assert.assertTrue(trc20[i + 1][0] > trc20[i][0]);
      Assert.assertTrue(trx[i + 1][2]   < trx[i][2]);
      Assert.assertTrue(trc20[i + 1][2] < trc20[i][2]);
    }
  }

  @Test
  public void mlDsa65AuthWitnessAlsoAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa65(1L);
    MLDSA65 kp = new MLDSA65();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.ML_DSA_65);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = MLDSA65.sign(kp.getPrivateKey(), digest);

    Transaction signed = tx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    Assert.assertTrue(cap.validatePubSignature(dbManager.getAccountStore(),
        dbManager.getDynamicPropertiesStore()));
  }

  @Test
  public void slhDsaAuthWitnessAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowSlhDsa(1L);
    SLHDSA kp = new SLHDSA();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.SLH_DSA);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = SLHDSA.sign(kp.getPrivateKey(), digest);

    Transaction signed = tx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    Assert.assertTrue(cap.validatePubSignature(dbManager.getAccountStore(),
        dbManager.getDynamicPropertiesStore()));
  }

  @Test
  public void slhDsaTamperedAuthWitnessRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowSlhDsa(1L);
    SLHDSA kp = new SLHDSA();
    putAccountWithPqPermission(PQ_OWNER_HEX, kp.getPublicKey(), SignatureScheme.SLH_DSA);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = SLHDSA.sign(kp.getPrivateKey(), digest);
    sig[0] ^= 0x01;

    Transaction signed = tx.toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(signerAddr))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("tampered SLH-DSA signature should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("pq sig invalid"));
    }
  }
}