package org.tron.common.crypto.curveparams;

import java.math.BigInteger;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class Secp256r1Params implements CurveParams {

  private static final String CURVE_NAME = "secp256r1";
  public static final ECDomainParameters CURVE;
  public static final ECParameterSpec CURVE_SPEC;
  public static final BigInteger HALF_CURVE_ORDER;

  private static final Secp256r1Params INSTANCE = new Secp256r1Params();

  static {
    try {
      X9ECParameters params = SECNamedCurves.getByName(CURVE_NAME);
      if (params == null) {
        throw new IllegalStateException("Failed to get secp256r1 parameters from SECNamedCurves");
      }
      CURVE = new ECDomainParameters(params.getCurve(), params.getG(),
          params.getN(), params.getH());
      CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(),
          params.getN(), params.getH());
      HALF_CURVE_ORDER = params.getN().shiftRight(1);
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize secp256r1 curve parameters", e);
    }
  }

  private Secp256r1Params() {
  }

  public static Secp256r1Params getInstance() {
    return INSTANCE;
  }

  @Override
  public String getCurveName() {
    return CURVE_NAME;
  }

  @Override
  public ECDomainParameters getCurve() {
    return CURVE;
  }

  @Override
  public ECParameterSpec getCurveSpec() {
    return CURVE_SPEC;
  }

  @Override
  public BigInteger getN() {
    return CURVE.getN();
  }

  @Override
  public BigInteger getHalfCurveOrder() {
    return HALF_CURVE_ORDER;
  }
}
