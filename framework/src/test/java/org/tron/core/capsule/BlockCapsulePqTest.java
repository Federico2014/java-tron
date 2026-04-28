package org.tron.core.capsule;

import com.google.protobuf.ByteString;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.MLDSA65;
import org.tron.common.crypto.pqc.PqAuthDigest;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.PqAuthWitness;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;
import org.tron.protos.Protocol.PqPublicKey;
import org.tron.protos.Protocol.SignatureScheme;

public class BlockCapsulePqTest extends BaseTest {

  private ECKey witnessKey;
  private byte[] witnessAddress;
  private MLDSA65 pqKeypair;

  @BeforeClass
  public static void init() {
    Args.setParam(new String[] {"-d", dbPath()}, TestConstants.TEST_CONF);
  }

  @Before
  public void setUp() {
    witnessKey = new ECKey();
    witnessAddress = witnessKey.getAddress();
    pqKeypair = new MLDSA65();
  }

  private AccountCapsule buildWitnessAccount(SignatureScheme scheme) {
    Key.Builder kb = Key.newBuilder()
        .setAddress(ByteString.copyFrom(witnessAddress))
        .setWeight(1);
    if (scheme == SignatureScheme.ML_DSA_65) {
      kb.setPqKey(PqPublicKey.newBuilder()
          .setScheme(scheme)
          .setPublicKey(ByteString.copyFrom(pqKeypair.getPublicKey()))
          .build());
    }
    Permission witnessPerm = Permission.newBuilder()
        .setType(PermissionType.Witness)
        .setId(1)
        .setPermissionName("witness")
        .setThreshold(1)
        .addKeys(kb)
        .build();
    Account account = Account.newBuilder()
        .setAccountName(ByteString.copyFromUtf8("w"))
        .setAddress(ByteString.copyFrom(witnessAddress))
        .setType(AccountType.Normal)
        .setBalance(1_000_000_000L)
        .setIsWitness(true)
        .setWitnessPermission(witnessPerm)
        .build();
    return new AccountCapsule(account);
  }

  private BlockCapsule buildSignedBlock(byte[] parentHash) {
    BlockCapsule block = new BlockCapsule(
        1L,
        Sha256Hash.wrap(ByteString.copyFrom(parentHash)),
        System.currentTimeMillis(),
        ByteString.copyFrom(witnessAddress));
    block.sign(witnessKey.getPrivKeyBytes());
    return block;
  }

  private BlockCapsule buildUnsignedBlock(byte[] parentHash) {
    return new BlockCapsule(
        1L,
        Sha256Hash.wrap(ByteString.copyFrom(parentHash)),
        System.currentTimeMillis(),
        ByteString.copyFrom(witnessAddress));
  }

  private byte[] signPq(byte[] message) {
    return MLDSA65.sign(pqKeypair.getPrivateKey(), message);
  }

  @Test
  public void legacyValidateWithoutPqAuthWitnessAcceptedBeforeActivation() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(0L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.UNKNOWN_SIG_SCHEME);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqWitnessBeforeActivationRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(0L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.UNKNOWN_SIG_SCHEME);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), 0);
    block.setPqWitness(PqAuthWitness.newBuilder()
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void bothLegacyAndPqAuthWitnessRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), 0);
    block.setPqWitness(PqAuthWitness.newBuilder()
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void mlDsaSchemeWithLegacyOnlyRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void legacySchemeWithPqAuthWitnessOnlyRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.UNKNOWN_SIG_SCHEME);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), 0);
    block.setPqWitness(PqAuthWitness.newBuilder()
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void neitherLegacyNorAuthRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test
  public void pqOnlyAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), 0);
    block.setPqWitness(PqAuthWitness.newBuilder()
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test
  public void tamperedPqAuthWitnessFails() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), 0);
    byte[] pqSig = signPq(digest);
    pqSig[pqSig.length - 1] ^= 0x01;
    block.setPqWitness(PqAuthWitness.newBuilder()
        .setSignature(ByteString.copyFrom(pqSig))
        .build());
    Assert.assertFalse(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void signerNotInWitnessPermissionRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), 1);
    block.setPqWitness(PqAuthWitness.newBuilder()
        .setKeyId(1)
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }
}
