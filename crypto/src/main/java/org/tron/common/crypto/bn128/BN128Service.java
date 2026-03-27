package org.tron.common.crypto.bn128;

import org.apache.commons.lang3.tuple.Pair;

/**
 * Common interface for BN128 elliptic curve operations via IPC.
 */
public interface BN128Service {

  /**
   * Performs BN128 point addition.
   *
   * @param input 128 bytes (two compressed G1 points)
   * @return Pair of (success, result bytes)
   */
  Pair<Boolean, byte[]> bn128Add(byte[] input) throws Exception;

  /**
   * Performs BN128 scalar multiplication.
   *
   * @param input 96 bytes (one compressed G1 point + scalar)
   * @return Pair of (success, result bytes)
   */
  Pair<Boolean, byte[]> bn128Mul(byte[] input) throws Exception;

  /**
   * Performs BN128 pairing check.
   *
   * @param input 192 bytes (pairing inputs)
   * @return Pair of (success, result bytes) - result is {1} if true, {0} if false
   */
  Pair<Boolean, byte[]> bn128Pairing(byte[] input) throws Exception;

  /**
   * Closes the service and releases resources.
   */
  void close() throws Exception;
}
