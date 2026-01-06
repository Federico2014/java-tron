/*
 * Copyright (c) [2016] [ <ether.camp> ]
 * This file is part of the ethereumJ library.
 *
 * The ethereumJ library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ethereumJ library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the ethereumJ library. If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.crypto.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import org.tron.common.crypto.curveparams.CurveParams;

public final class ECKeyPairGenerator {

  public static final String ALGORITHM = "EC";

  private static final String algorithmAssertionMsg =
      "Assumed JRE supports EC key pair generation";

  private static final String keySpecAssertionMsg =
      "Assumed correct key spec statically";

  private ECKeyPairGenerator() {
  }

  public static KeyPairGenerator getInstance(final String provider, final
  SecureRandom random, CurveParams curveParams) throws NoSuchProviderException {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance
          (ALGORITHM, provider);

      gen.initialize(curveParams.getCurveSpec(), random);
      return gen;
    } catch (NoSuchAlgorithmException ex) {
      throw new AssertionError(algorithmAssertionMsg, ex);
    } catch (InvalidAlgorithmParameterException ex) {
      throw new AssertionError(keySpecAssertionMsg, ex);
    }
  }

  public static KeyPairGenerator getInstance(final Provider provider, final
  SecureRandom random, CurveParams curveParams) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance
          (ALGORITHM, provider);
      gen.initialize(curveParams.getCurveSpec(), random);
      return gen;
    } catch (NoSuchAlgorithmException ex) {
      throw new AssertionError(algorithmAssertionMsg, ex);
    } catch (InvalidAlgorithmParameterException ex) {
      throw new AssertionError(keySpecAssertionMsg, ex);
    }
  }
}
