package org.tron.common.crypto;

import java.lang.reflect.InvocationTargetException;
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
import org.tron.common.crypto.pqc.Falcon;
import org.tron.common.utils.Sha256Hash;

import static org.junit.Assert.*;

/**
 * Unit tests for Falcon class
 * Tests various functionalities of the Falcon class
 */
@RunWith(Parameterized.class)
public class FalconTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private String algorithm;

  public FalconTest(String algorithm) {
    this.algorithm = algorithm;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        {Falcon.FALCON_512},
        {Falcon.FALCON_1024}
    });
  }

  @Test
  public void testConstructorWithAlgorithm() {
    // Test constructor with algorithm parameter
    Falcon falcon = new Falcon(algorithm);
    assertEquals(algorithm, falcon.getAlgorithm());
    assertNotNull(falcon.getPrivateKey());
    assertNotNull(falcon.getPublicKey());
  }

  @Test
  public void testDefaultConstructor() {
    // Test that default constructor creates Falcon-512 instance
    Falcon falcon = new Falcon();

    assertEquals(Falcon.FALCON_512, falcon.getAlgorithm());
    assertNotNull(falcon.getPrivateKey());
    assertNotNull(falcon.getPublicKey());
  }

  @Test
  public void testConstructorWithInvalidAlgorithm() {
    // Test that using invalid algorithm name throws exception
    thrown.expect(RuntimeException.class);
    new Falcon("InvalidAlgorithm");
  }

  @Test
  public void testConstructorWithKeyBytes() throws GeneralSecurityException {
    // First create a valid key pair
    Falcon original = new Falcon(algorithm);
    byte[] privateKeyBytes = original.getPrivateKeyBytes();
    byte[] publicKeyBytes = original.getPublicKeyBytes();

    // Construct new instance using byte arrays
    Falcon falcon = new Falcon(privateKeyBytes, publicKeyBytes, algorithm);

    assertEquals(algorithm, falcon.getAlgorithm());
    assertNotNull(falcon.getPrivateKey());
    assertNotNull(falcon.getPublicKey());
  }

  @Test
  public void testConstructorWithInvalidKeyBytes() throws GeneralSecurityException {
    // 1. null private key
    thrown.expect(IllegalArgumentException.class);
    new Falcon(null, new byte[1], algorithm);

    // 2. null public key
    thrown.expect(IllegalArgumentException.class);
    new Falcon(new byte[1], null, algorithm);

    // 3. empty private key
    thrown.expect(IllegalArgumentException.class);
    new Falcon(new byte[0], new byte[1], algorithm);

    // 4. empty public key
    thrown.expect(IllegalArgumentException.class);
    new Falcon(new byte[1], new byte[0], algorithm);
  }

  @Test
  public void testConstructorWithKeyBytesAndInvalidAlgorithm() throws GeneralSecurityException {
    // First create a valid key pair
    Falcon original = new Falcon(algorithm);
    byte[] privateKeyBytes = original.getPrivateKeyBytes();
    byte[] publicKeyBytes = original.getPublicKeyBytes();

    // Test that invalid algorithm name throws exception
    thrown.expect(IllegalArgumentException.class);
    new Falcon(privateKeyBytes, publicKeyBytes, "InvalidAlgorithm");
  }

  @Test
  public void testConstructorWithKeyPair() throws GeneralSecurityException {
    // Create original Falcon instance to get key pair
    Falcon original = new Falcon(algorithm);
    KeyPair keyPair = new KeyPair(original.getPublicKey(), original.getPrivateKey());

    // Construct new instance using KeyPair
    Falcon falcon = new Falcon(keyPair, algorithm);

    assertEquals(algorithm, falcon.getAlgorithm());
    assertNotNull(falcon.getPrivateKey());
    assertNotNull(falcon.getPublicKey());
  }

  @Test
  public void testConstructorWithNullKeyPair() throws GeneralSecurityException {
    // Test that null KeyPair throws exception
    thrown.expect(IllegalArgumentException.class);
    new Falcon(null, algorithm);
  }

  @Test
  public void testSignAndVerify() throws GeneralSecurityException {
    // Test signing and verification functionality
    Falcon falcon = new Falcon(algorithm);
    byte[] message = "Hello, Falcon!".getBytes();

    // Sign
    byte[] signature = falcon.sign(message);

    // Verify
    boolean isValid = falcon.verify(message, signature);

    assertTrue("Signature should be valid", isValid);
  }

  @Test
  public void testStaticSignAndVerify() throws GeneralSecurityException {
    // Test static signing and verification methods
    Falcon falcon = new Falcon(Falcon.FALCON_512);
    byte[] message = "Hello, Static Falcon!".getBytes();

    // Static signing
    byte[] signature = Falcon.sign(falcon.getPrivateKey(), message);

    // Static verification
    boolean isValid = Falcon.verify(falcon.getPublicKey(), message, signature);

    assertTrue("Static signature should be valid", isValid);
  }

  @Test
  public void testStaticSignAndVerify2() throws GeneralSecurityException {
    // Test static signing and verification methods
    Falcon falcon = new Falcon(algorithm);
    byte[] message = "Hello, Static Falcon!".getBytes();

    // Static signing
    byte[] signature = Falcon.sign(falcon.getPrivateKey(), message, algorithm);

    // Static verification
    boolean isValid = Falcon.verify(falcon.getPublicKey(), message, signature, algorithm);

    assertTrue("Static signature should be valid", isValid);
  }

  @Test
  public void testVerifyWithWrongSignature() throws GeneralSecurityException {
    // Test that using incorrect signature verification should return false
    Falcon falcon = new Falcon(algorithm);
    byte[] message1 = "Message 1".getBytes();
    byte[] message2 = "Message 2".getBytes();

    byte[] signature = falcon.sign(message1);

    // Verify signature with different message
    boolean isValid = falcon.verify(message2, signature);

    assertFalse("Verification should fail with wrong message", isValid);
  }

  @Test
  public void testGetKeyLengths() {
    // Test getting key length functionality
    Falcon falcon = new Falcon(algorithm);

    int publicKeyLength = falcon.getPublicKeyLength();
    int privateKeyLength = falcon.getPrivateKeyLength();

    assertTrue("Public key length should be positive", publicKeyLength > 0);
    assertTrue("Private key length should be positive", privateKeyLength > 0);
  }

  @Test
  public void testGetKeyBytes() {
    // Test getting key byte array functionality
    Falcon falcon = new Falcon(algorithm);

    byte[] publicKeyBytes = falcon.getPublicKeyBytes();
    byte[] privateKeyBytes = falcon.getPrivateKeyBytes();

    assertNotNull("Public key bytes should not be null", publicKeyBytes);
    assertNotNull("Private key bytes should not be null", privateKeyBytes);
    assertTrue("Public key bytes should not be empty", publicKeyBytes.length > 0);
    assertTrue("Private key bytes should not be empty", privateKeyBytes.length > 0);
  }

  @Test
  public void testDifferentAlgorithmsProduceDifferentResults() throws GeneralSecurityException {
    // Test that different algorithms produce different results
    Falcon falcon512 = new Falcon(Falcon.FALCON_512);
    Falcon falcon1024 = new Falcon(Falcon.FALCON_1024);

    assertNotEquals(falcon512.getAlgorithm(), falcon1024.getAlgorithm());

    byte[] message = "Test message".getBytes();
    byte[] signature512 = falcon512.sign(message);
    byte[] signature1024 = falcon1024.sign(message);

    // Signatures from different algorithms may have different lengths
    assertNotEquals("Signatures from different algorithms should have different lengths",
        signature512.length, signature1024.length);
  }

  // Additional test for algorithm validation
  @Test
  public void testCheckFalconAlgorithm() throws Exception {
    // Test algorithm validation functionality
    Method method = Falcon.class.getDeclaredMethod("checkFalconAlgorithm", String.class);
    method.setAccessible(true);

    // These should not throw exceptions
    try {
      method.invoke(null, Falcon.FALCON_512);
      method.invoke(null, Falcon.FALCON_1024);
    } catch (Exception e) {
      fail("Valid algorithms should not throw exceptions");
    }

    // test invalid algorithm
    try {
      method.invoke(null, "InvalidAlgorithm");
      fail("Should throw IllegalArgumentException");
    } catch (InvocationTargetException e) {
      assertTrue(e.getTargetException() instanceof IllegalArgumentException);
      assertTrue(
          e.getTargetException().getMessage().contains("Invalid Falcon signature algorithm"));
    }
  }

  // Test for key pair validation
  @Test
  public void testValidateKeyPair() throws Exception {
    // Test key pair validation functionality
    Falcon falcon = new Falcon(algorithm);

    // Correct key pair should pass validation
    Method method = Falcon.class.getDeclaredMethod("validateKeyPair",
        PrivateKey.class, PublicKey.class, String.class);
    method.setAccessible(true);

    boolean isValid = (Boolean) method.invoke(null, falcon.getPrivateKey(),
        falcon.getPublicKey(), algorithm);

    assertTrue("Valid key pair should pass validation", isValid);
  }

  @Ignore
  @Test
  public void testSignAndVerifyPerformance() throws GeneralSecurityException {
    Falcon falcon = new Falcon(algorithm);
    byte[] message = "Performance test message for Falcon signature".getBytes();
    byte[] hash = Sha256Hash.hash(true, message);

    int iterations = 10000;
    long totalSignTime = 0;
    long totalVerifyTime = 0;

    for (int i = 0; i < iterations; i++) {
      long signStartTime = System.nanoTime();
      byte[] signature = falcon.sign(hash);
      long signEndTime = System.nanoTime();
      totalSignTime += (signEndTime - signStartTime);

      long verifyStartTime = System.nanoTime();
      boolean isValid = falcon.verify(hash, signature);
      long verifyEndTime = System.nanoTime();
      totalVerifyTime += (verifyEndTime - verifyStartTime);

      assertTrue("Signature should be valid", isValid);
    }

    long avgSignTime = totalSignTime / iterations;
    long avgVerifyTime = totalVerifyTime / iterations;

    double avgSignTimeMs = avgSignTime / 1_000_000.0;
    double avgVerifyTimeMs = avgVerifyTime / 1_000_000.0;

    System.out.println("Falcon " + algorithm + " Performance Results:");
    System.out.println("Average sign time: " + avgSignTimeMs + " ms");
    System.out.println("Average verify time: " + avgVerifyTimeMs + " ms");
    System.out.println("Total iterations: " + iterations);
  }

  @Ignore
  @Test
  public void testSignAndVerifyPerformanceWithDifferentMessageSizes()
      throws GeneralSecurityException {
    Falcon falcon = new Falcon(algorithm);
    int[] messageSizes = {32, 64, 256, 1024, 4096};
    int iterations = 5000;

    System.out.println("Falcon " + algorithm + " Performance Results:");
    System.out.println("Total iterations: " + iterations);
    System.out.println("private key length: " + falcon.getPrivateKeyBytes().length);
    System.out.println("public key length: " + falcon.getPublicKeyBytes().length);

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
        byte[] signature = falcon.sign(message);
        long signEndTime = System.nanoTime();
        totalSignTime += (signEndTime - signStartTime);

        long verifyStartTime = System.nanoTime();
        boolean isValid = falcon.verify(message, signature);
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
