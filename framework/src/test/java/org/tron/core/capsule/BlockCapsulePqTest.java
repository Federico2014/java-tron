package org.tron.core.capsule;

import com.google.protobuf.ByteString;
import java.security.SecureRandom;
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
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.PqAuthDigest;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.AuthWitness;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;
import org.tron.protos.Protocol.SignatureScheme;

public class BlockCapsulePqTest extends BaseTest {

  private ECKey witnessKey;
  private byte[] witnessAddress;
  private MLDSAPrivateKeyParameters pqSk;
  private MLDSAPublicKeyParameters pqPk;

  @BeforeClass
  public static void init() {
    Args.setParam(new String[] {"-d", dbPath()}, TestConstants.TEST_CONF);
  }

  @Before
  public void setUp() {
    witnessKey = new ECKey();
    witnessAddress = witnessKey.getAddress();
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
    AsymmetricCipherKeyPair kp = gen.generateKeyPair();
    pqPk = (MLDSAPublicKeyParameters) kp.getPublic();
    pqSk = (MLDSAPrivateKeyParameters) kp.getPrivate();
  }

  private AccountCapsule buildWitnessAccount(SignatureScheme scheme) {
    Key.Builder kb = Key.newBuilder()
        .setAddress(ByteString.copyFrom(witnessAddress))
        .setWeight(1)
        .setScheme(scheme);
    if (scheme == SignatureScheme.ML_DSA_65) {
      kb.setPublicKey(ByteString.copyFrom(pqPk.getEncoded()));
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
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, pqSk);
    signer.update(message, 0, message.length);
    try {
      return signer.generateSignature();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void legacyValidateWithoutAuthWitnessAcceptedBeforeActivation() throws Exception {
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
  public void authWitnessBeforeActivationRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(0L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.UNKNOWN_SIG_SCHEME);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), witnessAddress);
    block.setWitnessAuth(AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(witnessAddress))
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void bothLegacyAndAuthWitnessRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), witnessAddress);
    block.setWitnessAuth(AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(witnessAddress))
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
  public void legacySchemeWithAuthWitnessOnlyRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.UNKNOWN_SIG_SCHEME);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), witnessAddress);
    block.setWitnessAuth(AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(witnessAddress))
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
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), witnessAddress);
    block.setWitnessAuth(AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(witnessAddress))
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test
  public void tamperedAuthWitnessFails() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa(1L);
    AccountCapsule witness = buildWitnessAccount(SignatureScheme.ML_DSA_65);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), witnessAddress);
    byte[] pqSig = signPq(digest);
    pqSig[pqSig.length - 1] ^= 0x01;
    block.setWitnessAuth(AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(witnessAddress))
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
    byte[] otherAddr = ByteArray.fromHexString(
        "41" + "abababababababababababababababababababab");
    byte[] digest = PqAuthDigest.block(block.getRawHashBytes(), otherAddr);
    block.setWitnessAuth(AuthWitness.newBuilder()
        .setSignerAddress(ByteString.copyFrom(otherAddr))
        .setSignature(ByteString.copyFrom(signPq(digest)))
        .build());
    block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }
}
