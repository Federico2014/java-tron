package org.tron.core.consensus;

import static org.tron.common.utils.ByteArray.fromHexString;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.parameter.CommonParameter;
import org.tron.consensus.Consensus;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.exception.TronError;
import org.tron.core.store.WitnessStore;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "consensus")
@Component
public class ConsensusService {

  @Autowired
  private Consensus consensus;

  @Autowired
  private WitnessStore witnessStore;

  @Autowired
  private BlockHandleImpl blockHandle;

  @Autowired
  private PbftBaseImpl pbftBaseImpl;

  private CommonParameter parameter = Args.getInstance();

  public void start() {
    Param param = Param.getInstance();
    param.setEnable(parameter.isWitness());
    param.setGenesisBlock(parameter.getGenesisBlock());
    param.setMinParticipationRate(parameter.getMinParticipationRate());
    param.setBlockProduceTimeoutPercent(Args.getInstance().getBlockProducedTimeOut());
    param.setNeedSyncCheck(parameter.isNeedSyncCheck());
    param.setAgreeNodeCount(parameter.getAgreeNodeCount());
    List<Miner> miners = new ArrayList<>();
    List<String> privateKeys = Args.getLocalWitnesses().getPrivateKeys();
    List<String> pqPrivateKeys = Args.getLocalWitnesses().getPqPrivateKeys();
    List<String> pqPublicKeys = Args.getLocalWitnesses().getPqPublicKeys();
    if (pqPublicKeys.size() != pqPrivateKeys.size()) {
      throw new TronError(
          "localwitness_pq_keys size mismatch: " + pqPrivateKeys.size()
              + " private vs " + pqPublicKeys.size() + " public",
          TronError.ErrCode.WITNESS_INIT);
    }
    if (privateKeys.size() > 1) {
      for (String key : privateKeys) {
        byte[] privateKey = fromHexString(key);
        byte[] privateKeyAddress = SignUtils
            .fromPrivate(privateKey, Args.getInstance().isECKeyCryptoEngine()).getAddress();
        WitnessCapsule witnessCapsule = witnessStore.get(privateKeyAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(privateKeyAddress));
        }
        Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
            ByteString.copyFrom(privateKeyAddress));
        miners.add(miner);
        logger.info("Add witness: {}, size: {}",
            Hex.toHexString(privateKeyAddress), miners.size());
      }
    } else if (privateKeys.size() == 1) {
      byte[] privateKey =
          fromHexString(Args.getLocalWitnesses().getPrivateKey());
      byte[] privateKeyAddress = SignUtils.fromPrivate(privateKey,
          Args.getInstance().isECKeyCryptoEngine()).getAddress();
      byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
      WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
      if (null == witnessCapsule) {
        logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
      }
      // In multi-signature mode, the address derived from the private key may differ from
      // witnessAddress.
      Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
          ByteString.copyFrom(witnessAddress));
      miners.add(miner);
    } else if (pqPrivateKeys.size() > 1) {
      PQScheme scheme = Args.getLocalWitnesses().getPqScheme();
      requireSupportedPqScheme(scheme);
      for (int i = 0; i < pqPrivateKeys.size(); i++) {
        byte[] privBytes = fromHexString(pqPrivateKeys.get(i));
        byte[] pubBytes = fromHexString(pqPublicKeys.get(i));
        PQSignature keypair = PQSchemeRegistry.fromKeypair(scheme, privBytes, pubBytes);
        byte[] sk = keypair.getPrivateKey();
        byte[] pk = keypair.getPublicKey();
        byte[] pqAddress = keypair.getAddress();
        WitnessCapsule witnessCapsule = witnessStore.get(pqAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(pqAddress));
        }
        ByteString pqAddressBs = ByteString.copyFrom(pqAddress);
        Miner miner = param.new Miner(null, pqAddressBs, pqAddressBs);
        miner.setPQPrivateKey(sk);
        miner.setPQPublicKey(pk);
        miner.setPqScheme(scheme);
        miners.add(miner);
        logger.info("Add {} witness (from configured keypair): {}, size: {}",
            scheme, Hex.toHexString(pqAddress), miners.size());
      }
    } else if (pqPrivateKeys.size() == 1) {
      miners.add(buildPQOnlyMinerFromKeypair(param, pqPrivateKeys.get(0), pqPublicKeys.get(0)));
    }

    param.setMiners(miners);
    param.setBlockHandle(blockHandle);
    param.setPbftInterface(pbftBaseImpl);
    consensus.start(param);
    logger.info("consensus service start success");
  }

  private Miner buildPQOnlyMinerFromKeypair(Param param, String pqPrivateKey,
      String pqPublicKey) {
    PQScheme scheme = Args.getLocalWitnesses().getPqScheme();
    requireSupportedPqScheme(scheme);
    byte[] privBytes = fromHexString(pqPrivateKey);
    byte[] pubBytes = fromHexString(pqPublicKey);
    PQSignature keypair = PQSchemeRegistry.fromKeypair(scheme, privBytes, pubBytes);
    byte[] sk = keypair.getPrivateKey();
    byte[] pk = keypair.getPublicKey();
    byte[] pqAddress = keypair.getAddress();
    byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
    if (witnessAddress == null || witnessAddress.length == 0) {
      witnessAddress = pqAddress;
    }
    WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
    if (null == witnessCapsule) {
      logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
    }
    // In multi-signature mode, the address derived from the PQ key may differ from witnessAddress.
    Miner miner = param.new Miner(null, ByteString.copyFrom(pqAddress),
        ByteString.copyFrom(witnessAddress));
    miner.setPQPrivateKey(sk);
    miner.setPQPublicKey(pk);
    miner.setPqScheme(scheme);
    logger.info("Add {} witness (from configured keypair): {}",
        scheme, Hex.toHexString(witnessAddress));
    return miner;
  }

  private static void requireSupportedPqScheme(PQScheme scheme) {
    if (!PQSchemeRegistry.contains(scheme)) {
      throw new TronError("unsupported PQ witness scheme: " + scheme,
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  public void stop() {
    logger.info("consensus service closed start.");
    consensus.stop();
    logger.info("consensus service closed successfully.");
  }

}
