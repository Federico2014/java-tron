package org.tron.core.capsule;

import static org.tron.protos.Protocol.Transaction.Result.contractResult.BAD_JUMP_DESTINATION;
import static org.tron.protos.Protocol.Transaction.Result.contractResult.PRECOMPILED_CONTRACT;
import static org.tron.protos.Protocol.Transaction.Result.contractResult.SUCCESS;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.security.SecureRandom;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
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

  private AsymmetricCipherKeyPair newMlDsa65KeyPair() {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
    return gen.generateKeyPair();
  }

  private byte[] sign(MLDSAPrivateKeyParameters sk, byte[] msg) throws Exception {
    MLDSASigner s = new MLDSASigner();
    s.init(true, sk);
    s.update(msg, 0, msg.length);
    return s.generateSignature();
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

  private void putAccountWithMlDsa65Permission(String ownerHex, byte[] pqPublicKey) {
    byte[] addr = ByteArray.fromHexString(ownerHex);
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    Key pqKey = Key.newBuilder()
        .setAddress(ByteString.copyFrom(signerAddr))
        .setWeight(1L)
        .setScheme(SignatureScheme.ML_DSA_65)
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
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(0L);
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0).toBuilder()
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(ByteArray.fromHexString(PQ_SIGNER_HEX)))
            .setSignature(ByteString.copyFrom(new byte[3309]))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(tx);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(),
          dbManager.getDynamicPropertiesStore());
      Assert.fail("should reject auth_witness before activation");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("ML-DSA not activated"));
    }
  }

  @Test
  public void signatureAndAuthWitnessAreMutuallyExclusive() {
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0).toBuilder()
        .addSignature(ByteString.copyFrom(new byte[65]))
        .addAuthWitness(AuthWitness.newBuilder()
            .setSignerAddress(ByteString.copyFrom(ByteArray.fromHexString(PQ_SIGNER_HEX)))
            .setSignature(ByteString.copyFrom(new byte[3309]))
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
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AsymmetricCipherKeyPair kp = newMlDsa65KeyPair();
    byte[] pkBytes = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    putAccountWithMlDsa65Permission(PQ_OWNER_HEX, pkBytes);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = sign(sk, digest);

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
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AsymmetricCipherKeyPair kp = newMlDsa65KeyPair();
    byte[] pkBytes = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    putAccountWithMlDsa65Permission(PQ_OWNER_HEX, pkBytes);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = sign(sk, digest);
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
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AsymmetricCipherKeyPair kp = newMlDsa65KeyPair();
    byte[] pkBytes = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    putAccountWithMlDsa65Permission(PQ_OWNER_HEX, pkBytes);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] signerAddr = ByteArray.fromHexString(PQ_SIGNER_HEX);
    byte[] digest = PqAuthDigest.tx(txid, 0, signerAddr);
    byte[] sig = sign(sk, digest);
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
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AsymmetricCipherKeyPair kp = newMlDsa65KeyPair();
    byte[] pkBytes = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    putAccountWithMlDsa65Permission(PQ_OWNER_HEX, pkBytes);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = Sha256Hash.of(true, tx.getRawData().toByteArray()).getBytes();
    byte[] otherSigner = ByteArray.fromHexString(
        "41BCE23C7D683B889326F762DDA2223A861EDA2E5C");
    byte[] digest = PqAuthDigest.tx(txid, 0, otherSigner);
    byte[] sig = sign(sk, digest);

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
}