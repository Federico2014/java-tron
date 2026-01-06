package org.tron.common.crypto.curveparams;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;

public interface CurveParams {

  String getCurveName();

  ECDomainParameters getCurve();

  ECParameterSpec getCurveSpec();

  BigInteger getN();

  /**
   * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. ECDSA
   * signatures are mutable in the sense that for a given (R, S) pair, then both (R, S) and (R, N -
   * S mod N) are valid signatures. Canonical signatures are those where 1 <= S <= N/2
   *
   * <p>See https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
   * #Low_S_values_in_signatures
   */
  BigInteger getHalfCurveOrder();
}

