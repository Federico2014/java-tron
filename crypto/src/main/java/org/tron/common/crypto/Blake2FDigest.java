package org.tron.common.crypto;

import java.security.MessageDigest;
import lombok.Setter;
import org.hyperledger.besu.nativelib.blake2bf.LibBlake2bf;

public class Blake2FDigest {

  @Setter
  private static boolean useBlake2FV2 = false;

  public static byte[] blake2f(byte[] data) {
    byte[] result = new byte[64];
    if (useBlake2FV2 && LibBlake2bf.ENABLED) {
      LibBlake2bf.blake2bf_eip152(result, data);
    } else {
      final MessageDigest digest = new Blake2bfMessageDigest();
      digest.update(data);
      result = digest.digest();
    }
    return result;
  }
}
