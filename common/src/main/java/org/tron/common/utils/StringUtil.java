/*
 * java-tron is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * java-tron is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.utils;

import com.google.protobuf.ByteString;

public class StringUtil {

  public static byte[] createDbKey(ByteString string) {
    return string.toByteArray();
  }

  public static String createReadableString(byte[] bytes) {
    return ByteArray.toHexString(bytes);
  }

  public static String encode58Check(byte[] input) {
    byte[] hash0 = Sha256Hash.hash(input);
    byte[] hash1 = Sha256Hash.hash(hash0);
    byte[] inputCheck = new byte[input.length + 4];
    System.arraycopy(input, 0, inputCheck, 0, input.length);
    System.arraycopy(hash1, 0, inputCheck, input.length, 4);
    return Base58.encode(inputCheck);
  }

  public static String createReadableString(ByteString string) {
    return createReadableString(string.toByteArray());
  }

  public static ByteString hexString2ByteString(String hexString) {
    return ByteString.copyFrom(ByteArray.fromHexString(hexString));
  }

  /**
   * Checks for non-empty, even-length ASCII hex with an optional {@code 0x} prefix.
   */
  public static boolean isHexadecimal(String str) {
    if (str == null || str.isEmpty()) {
      return false;
    }
    int start = str.startsWith("0x") ? 2 : 0;
    if (str.length() == start || str.length() % 2 != 0) {
      return false;
    }

    for (int i = start; i < str.length(); i++) {
      char c = str.charAt(i);
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
          || (c >= 'A' && c <= 'F'))) {
        return false;
      }
    }
    return true;
  }
}
