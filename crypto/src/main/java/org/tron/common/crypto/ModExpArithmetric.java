package org.tron.common.crypto;

import static org.tron.common.utils.BIUtil.addSafely;
import static org.tron.common.utils.BIUtil.isZero;
import static org.tron.common.utils.ByteUtil.EMPTY_BYTE_ARRAY;
import static org.tron.common.utils.ByteUtil.bytesToBigInteger;
import static org.tron.common.utils.ByteUtil.parseBytes;
import static org.tron.common.utils.ByteUtil.stripLeadingZeroes;

import com.sun.jna.ptr.IntByReference;
import java.math.BigInteger;
import lombok.Setter;
import org.hyperledger.besu.nativelib.arithmetic.LibArithmetic;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.utils.ByteArray;

public class ModExpArithmetric {

  @Setter
  private static boolean useModExpV2 = false;

  private static final int ARGS_OFFSET = 32 * 3; // addresses length part

  public static byte[] modExp(byte[] data) {
    int baseLen = parseLen(data, 0);
    int expLen = parseLen(data, 1);
    int modLen = parseLen(data, 2);

    byte[] res;
    if (useModExpV2 && LibArithmetic.ENABLED) {
      byte[] resultArray = new byte[modLen];
      IntByReference resultSize = new IntByReference(resultArray.length);
      LibArithmetic.modexp_precompiled(data, data.length, resultArray, resultSize);
      res = ByteArray.subArray(resultArray, 0, resultSize.getValue());
    } else {
      BigInteger base = parseArg(data, ARGS_OFFSET, baseLen);
      BigInteger exp = parseArg(data, addSafely(ARGS_OFFSET, baseLen), expLen);
      BigInteger mod = parseArg(data, addSafely(addSafely(ARGS_OFFSET, baseLen), expLen), modLen);

      // check if modulus is zero
      if (isZero(mod)) {
        return EMPTY_BYTE_ARRAY;
      }
      res =  stripLeadingZeroes(base.modPow(exp, mod).toByteArray());
    }

    if (res.length < modLen) {
      byte[] adjRes = new byte[modLen];
      System.arraycopy(res, 0, adjRes, modLen - res.length, res.length);
      return adjRes;
    }
    return res;
  }

  private static int parseLen(byte[] data, int idx) {
    byte[] bytes = parseBytes(data, 32 * idx, 32);
    return new DataWord(bytes).intValueSafe();
  }

  private static BigInteger parseArg(byte[] data, int offset, int len) {
    byte[] bytes = parseBytes(data, offset, len);
    return bytesToBigInteger(bytes);
  }
}
