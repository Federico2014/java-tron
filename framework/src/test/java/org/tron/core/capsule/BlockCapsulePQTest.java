package org.tron.core.capsule;

import com.google.protobuf.ByteString;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;

public class BlockCapsulePQTest extends BaseTest {

  private ECKey witnessKey;
  private byte[] witnessAddress;
  private FNDSA pqKeypair;
  private byte[] pqAddress;

  @BeforeClass
  public static void init() {
    Args.setParam(new String[] {"-d", dbPath()}, TestConstants.TEST_CONF);
  }

  @Before
  public void setUp() {
    witnessKey = new ECKey();
    witnessAddress = witnessKey.getAddress();
    pqKeypair = new FNDSA();
    pqAddress = PQSchemeRegistry.computeAddress(
        PQScheme.FN_DSA_512, pqKeypair.getPublicKey());
  }

  /**
   * Build a witness account whose witness permission key is bound to the
   * given address. For PQ scenarios, pass {@link #pqAddress}; for legacy ECDSA
   * scenarios, pass {@link #witnessAddress}.
   */
  private AccountCapsule buildWitnessAccount(byte[] keyAddress) {
    Key kb = Key.newBuilder()
        .setAddress(ByteString.copyFrom(keyAddress))
        .setWeight(1)
        .build();
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

  private byte[] signPQ(byte[] message) {
    return FNDSA.sign(pqKeypair.getPrivateKey(), message);
  }

  private PQAuthSig buildPQAuthSig(byte[] signature) {
    return PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(pqKeypair.getPublicKey()))
        .setSignature(ByteString.copyFrom(signature))
        .build();
  }

  @Test
  public void legacyValidateWithoutPQAuthSigAcceptedBeforeActivation() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    AccountCapsule witness = buildWitnessAccount(witnessAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigBeforeActivationRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void bothLegacyAndPQAuthSigRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test
  public void pqOnlyAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test
  public void tamperedPQAuthSigFails() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    byte[] pqSig = signPQ(digest);
    pqSig[pqSig.length - 1] ^= 0x01;
    block.setPqAuthSig(buildPQAuthSig(pqSig));
    Assert.assertFalse(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void signerNotInWitnessPermissionRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    // Witness permission key bound to a different address (the legacy ECDSA
    // address), so the PQ signer's derived address won't match.
    AccountCapsule witness = buildWitnessAccount(witnessAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }
}
