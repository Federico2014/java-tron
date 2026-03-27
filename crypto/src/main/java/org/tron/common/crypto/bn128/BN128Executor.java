package org.tron.common.crypto.bn128;

import com.sun.jna.ptr.IntByReference;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.hyperledger.besu.nativelib.gnark.LibGnarkEIP196;

@Slf4j(topic = "crypto")
public class BN128Executor {

  public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  private static final int PAIR_SIZE = 192;

  // Limit to 100 pairs (19,200 bytes) in optimized mode to prevent timeout attacks
  private static final int MAX_PAIR_SIZE_LIMIT = 192 * 100;

  public static Pair<Boolean, byte[]> add(byte[] data) {
    if (data == null) {
      data = EMPTY_BYTE_ARRAY;
    }

    byte[] input = data.length > 128
        ? Arrays.copyOfRange(data, 0, 128) : data;
    Pair<Boolean, byte[]> result = executeEIP196Operation(
        LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE, input);
    return result;
  }

  public static Pair<Boolean, byte[]> mul(byte[] data) {
    if (data == null) {
      data = EMPTY_BYTE_ARRAY;
    }

    byte[] input = data.length > 96
        ? Arrays.copyOfRange(data, 0, 96) : data;
    Pair<Boolean, byte[]> result = executeEIP196Operation(
        LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE, input);
    return result;
  }

  public static Pair<Boolean, byte[]> pairing(byte[] data) {
    if (data == null) {
      data = EMPTY_BYTE_ARRAY;
    }

    if (data.length > MAX_PAIR_SIZE_LIMIT
        || data.length % PAIR_SIZE > 0) {
      return Pair.of(false, EMPTY_BYTE_ARRAY);
    }
    Pair<Boolean, byte[]> result = executeEIP196Operation(
        LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE, data);
    return result;

  }


  private static Pair<Boolean, byte[]> executeEIP196Operation(
      byte operation, byte[] data) {
    if (!LibGnarkEIP196.ENABLED) {
      logger.warn("Native BN128 library not available, "
          + "cannot execute optimized path");
      return null;
    }

    final byte[] output =
        new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
    final IntByReference outputLength = new IntByReference();
    final byte[] error =
        new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_ERROR_BYTES];
    final IntByReference errorLength = new IntByReference();

    int ret = LibGnarkEIP196.eip196_perform_operation(
        operation, data, data.length,
        output, outputLength, error, errorLength);

    if (ret == 0) {
      return Pair.of(true,
          subArray(output, 0, outputLength.getValue()));
    } else {
      return Pair.of(false, EMPTY_BYTE_ARRAY);
    }
  }

  public static byte[] subArray(byte[] input, int start, int end) {
    byte[] result = new byte[end - start];
    System.arraycopy(input, start, result, 0, end - start);
    return result;
  }

}
