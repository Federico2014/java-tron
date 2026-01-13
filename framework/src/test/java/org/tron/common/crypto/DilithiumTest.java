package org.tron.common.crypto;

import java.lang.reflect.Method;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.*;
import java.util.Arrays;
import java.util.Collection;
import org.tron.common.crypto.pqc.Dilithium;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.tron.common.utils.Sha256Hash;

import static org.junit.Assert.*;

/**
 * Unit tests for Dilithium class Tests various functionalities of the Dilithium class
 */
@RunWith(Parameterized.class)
public class DilithiumTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private DilithiumParameterSpec parameterSpec;

  public DilithiumTest(DilithiumParameterSpec parameterSpec) {
    this.parameterSpec = parameterSpec;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        {Dilithium.DILITHIUM2},
        {Dilithium.DILITHIUM3},
        {Dilithium.DILITHIUM5}
    });
  }

  @Test
  public void testConstructorWithParameterSpec() {
    // Test constructor with parameter specification
    Dilithium dilithium = new Dilithium(parameterSpec);
    assertEquals(parameterSpec, dilithium.getParameterSpec());
    assertNotNull(dilithium.getPrivateKey());
    assertNotNull(dilithium.getPublicKey());
  }

  @Test
  public void testDefaultConstructor() {
    // Test that default constructor creates Dilithium2 instance
    Dilithium dilithium = new Dilithium();

    assertEquals(Dilithium.DILITHIUM2, dilithium.getParameterSpec());
    assertNotNull(dilithium.getPrivateKey());
    assertNotNull(dilithium.getPublicKey());
  }

  @Test
  public void testConstructorWithKeyBytes() throws GeneralSecurityException {
    // First create a valid key pair
    Dilithium original = new Dilithium(parameterSpec);
    byte[] privateKeyBytes = original.getPrivateKeyBytes();
    byte[] publicKeyBytes = original.getPublicKeyBytes();

    // Construct new instance using byte arrays
    Dilithium dilithium = new Dilithium(privateKeyBytes, publicKeyBytes);
    assertNotNull(dilithium.getPrivateKey());
    assertNotNull(dilithium.getPublicKey());
  }

  @Test
  public void testConstructorWithInvalidKeyBytes() throws GeneralSecurityException {
    // 1. null private key
    thrown.expect(IllegalArgumentException.class);
    new Dilithium(null, new byte[1]);

    // 2. null public key
    thrown.expect(IllegalArgumentException.class);
    new Dilithium(new byte[1], null);

    // 3. empty private key
    thrown.expect(IllegalArgumentException.class);
    new Dilithium(new byte[0], new byte[1]);

    // 4. empty public key
    thrown.expect(IllegalArgumentException.class);
    new Dilithium(new byte[1], new byte[0]);
  }

  @Test
  public void testConstructorWithKeyPair() throws GeneralSecurityException {
    // Create original Dilithium instance to get key pair
    Dilithium original = new Dilithium(parameterSpec);
    KeyPair keyPair = new KeyPair(original.getPublicKey(), original.getPrivateKey());

    // Construct new instance using KeyPair
    Dilithium dilithium = new Dilithium(keyPair);

    assertNotNull(dilithium.getPrivateKey());
    assertNotNull(dilithium.getPublicKey());
  }

  @Test
  public void testConstructorWithNullKeyPair() throws GeneralSecurityException {
    // Test that null KeyPair throws exception
    thrown.expect(IllegalArgumentException.class);
    new Dilithium(null, null);
  }

  @Test
  public void testConstructorWithNullKeyPairAndParameterSpec() throws GeneralSecurityException {
    // Test that null KeyPair and null parameter spec throws exception
    thrown.expect(IllegalArgumentException.class);
    new Dilithium((KeyPair) null);
  }

  @Test
  public void testSignAndVerify() throws GeneralSecurityException {
    // Test signing and verification functionality
    Dilithium dilithium = new Dilithium(parameterSpec);
    byte[] message = Sha256Hash.hash(true, "Hello, Dilithium!".getBytes());

    // Sign
    byte[] signature = dilithium.sign(message);

    // Verify
    boolean isValid = dilithium.verify(message, signature);

    assertTrue("Signature should be valid", isValid);
  }

  @Test
  public void testStaticSignAndVerify() throws GeneralSecurityException {
    // Test static signing and verification methods
    Dilithium dilithium = new Dilithium(parameterSpec);
    byte[] message = Sha256Hash.hash(true, "Hello, Static Dilithium!".getBytes());

    // Static signing
    byte[] signature = Dilithium.sign(dilithium.getPrivateKey(), message);

    // Static verification
    boolean isValid = Dilithium.verify(dilithium.getPublicKey(), message, signature);

    assertTrue("Static signature should be valid", isValid);
  }

  @Test
  public void testVerifyWithWrongSignature() throws GeneralSecurityException {
    // Test that using incorrect signature verification should return false
    Dilithium dilithium = new Dilithium(parameterSpec);
    byte[] message1 = "Message 1".getBytes();
    byte[] message2 = "Message 2".getBytes();

    byte[] signature = dilithium.sign(message1);

    // Verify signature with different message
    boolean isValid = dilithium.verify(message2, signature);

    assertFalse("Verification should fail with wrong message", isValid);
  }

  @Test
  public void testGetKeyLengths() {
    // Test getting key length functionality
    Dilithium dilithium = new Dilithium(parameterSpec);

    int publicKeyLength = dilithium.getPublicKeyLength();
    int privateKeyLength = dilithium.getPrivateKeyLength();

    assertTrue("Public key length should be positive", publicKeyLength > 0);
    assertTrue("Private key length should be positive", privateKeyLength > 0);
  }

  @Test
  public void testGetKeyBytes() {
    // Test getting key byte array functionality
    Dilithium dilithium = new Dilithium(parameterSpec);

    byte[] publicKeyBytes = dilithium.getPublicKeyBytes();
    byte[] privateKeyBytes = dilithium.getPrivateKeyBytes();

    assertNotNull("Public key bytes should not be null", publicKeyBytes);
    assertNotNull("Private key bytes should not be null", privateKeyBytes);
    assertTrue("Public key bytes should not be empty", publicKeyBytes.length > 0);
    assertTrue("Private key bytes should not be empty", privateKeyBytes.length > 0);
  }

  @Test
  public void testDifferentParameterSpecsProduceDifferentResults() throws GeneralSecurityException {
    // Test that different parameter specs produce different results
    Dilithium dilithium2 = new Dilithium(Dilithium.DILITHIUM2);
    Dilithium dilithium3 = new Dilithium(Dilithium.DILITHIUM3);
    Dilithium dilithium5 = new Dilithium(Dilithium.DILITHIUM5);

    byte[] message = "Test message".getBytes();
    byte[] signature2 = dilithium2.sign(message);
    byte[] signature3 = dilithium3.sign(message);
    byte[] signature5 = dilithium5.sign(message);

    // Signatures from different parameter specs may have different lengths
    assertNotEquals("Signatures from different parameter specs should have different lengths",
        signature2.length, signature3.length);
    assertNotEquals("Signatures from different parameter specs should have different lengths",
        signature2.length, signature5.length);
    assertNotEquals("Signatures from different parameter specs should have different lengths",
        signature3.length, signature5.length);
  }

  @Test
  public void testValidateKeyPair() throws Exception {
    // Test key pair validation functionality
    Dilithium dilithium = new Dilithium(parameterSpec);

    // Correct key pair should pass validation
    Method method = Dilithium.class.getDeclaredMethod("validateKeyPair",
        PrivateKey.class, PublicKey.class);
    method.setAccessible(true);

    boolean isValid = (Boolean) method.invoke(null, dilithium.getPrivateKey(),
        dilithium.getPublicKey());

    assertTrue("Valid key pair should pass validation", isValid);
  }

  @Ignore
  @Test
  public void testSignAndVerifyPerformance() throws GeneralSecurityException {
    Dilithium dilithium = new Dilithium(parameterSpec);
    byte[] message = "Performance test message for Dilithium signature".getBytes();
    byte[] hash = Sha256Hash.hash(true, message);

    int iterations = 10000;
    long totalSignTime = 0;
    long totalVerifyTime = 0;

    for (int i = 0; i < iterations; i++) {
      long signStartTime = System.nanoTime();
      byte[] signature = dilithium.sign(hash);
      long signEndTime = System.nanoTime();
      totalSignTime += (signEndTime - signStartTime);

      long verifyStartTime = System.nanoTime();
      boolean isValid = dilithium.verify(hash, signature);
      long verifyEndTime = System.nanoTime();
      totalVerifyTime += (verifyEndTime - verifyStartTime);

      assertTrue("Signature should be valid", isValid);
    }

    long avgSignTime = totalSignTime / iterations;
    long avgVerifyTime = totalVerifyTime / iterations;

    double avgSignTimeMs = avgSignTime / 1_000_000.0;
    double avgVerifyTimeMs = avgVerifyTime / 1_000_000.0;

    System.out.println("Dilithium " + parameterSpec.getName() + " Performance Results:");
    System.out.println("Average sign time: " + avgSignTimeMs + " ms");
    System.out.println("Average verify time: " + avgVerifyTimeMs + " ms");
    System.out.println("Total iterations: " + iterations);
  }

  @Ignore
  @Test
  public void testSignAndVerifyPerformanceWithDifferentMessageSizes()
      throws GeneralSecurityException {
    Dilithium dilithium = new Dilithium(parameterSpec);
    int[] messageSizes = {32, 64, 256, 1024, 4096};
    int iterations = 500;

    System.out.println("Dilithium " + parameterSpec.getName() + " Performance Results:");
    System.out.println("Total iterations: " + iterations);
    System.out.println("private key length: " + dilithium.getPrivateKeyBytes().length);
    System.out.println("public key length: " + dilithium.getPublicKeyBytes().length);

    for (int size : messageSizes) {
      byte[] message = new byte[size];
      for (int i = 0; i < size; i++) {
        message[i] = (byte) (i % 256);
      }

      long totalSignTime = 0;
      long totalVerifyTime = 0;
      int minSigLength = Integer.MAX_VALUE;
      int maxSigLength = 0;

      for (int i = 0; i < iterations; i++) {
        long signStartTime = System.nanoTime();
        byte[] signature = dilithium.sign(message);
        long signEndTime = System.nanoTime();
        totalSignTime += (signEndTime - signStartTime);

        long verifyStartTime = System.nanoTime();
        boolean isValid = dilithium.verify(message, signature);
        long verifyEndTime = System.nanoTime();
        totalVerifyTime += (verifyEndTime - verifyStartTime);
        assertTrue("Signature should be valid for size " + size, isValid);

        minSigLength = Math.min(minSigLength, signature.length);
        maxSigLength = Math.max(maxSigLength, signature.length);
      }

      double avgSignTimeMs = (totalSignTime / iterations) / 1_000_000.0;
      double avgVerifyTimeMs = (totalVerifyTime / iterations) / 1_000_000.0;

      System.out.println("Message size: " + size + " bytes");
      System.out.println("  Average sign time: " + avgSignTimeMs + " ms");
      System.out.println("  Average verify time: " + avgVerifyTimeMs + " ms");
      System.out.println("  Min signature length: " + minSigLength);
      System.out.println("  Max signature length: " + maxSigLength);
    }
  }
}
