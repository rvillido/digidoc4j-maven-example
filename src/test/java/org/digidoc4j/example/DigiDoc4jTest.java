package org.digidoc4j.example;

import eu.europa.esig.dss.MimeType;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.*;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DigiDoc4jTest {

	public static final String SIGNATURE_TOKEN_PATH = "src/test/resources/signature_token.p12";
	public static final String SIGNATURE_TOKEN_PASSWORD = "test";
	public static final String EXAMPLE_BDOC_CONTAINER_PATH = "src/test/resources/valid_bdoc_ts_signature.bdoc";
	private final Configuration configuration = new Configuration(Configuration.Mode.TEST);
	private PKCS12SignatureToken testSignatureToken;
	private File testFile;

	@Rule
	public TemporaryFolder testFolder = new TemporaryFolder();

	@Before
	public void setUp() throws Exception {
		testSignatureToken = new PKCS12SignatureToken(SIGNATURE_TOKEN_PATH, SIGNATURE_TOKEN_PASSWORD.toCharArray());
		testFile = createTestFile();
	}

	@Test
	public void createAndValidateBDocTMContainer() throws Exception {
		Container container = createAndValidateContainer(SignatureProfile.LT_TM, ContainerBuilder.BDOC_CONTAINER_TYPE, DigestAlgorithm.SHA256);
		assertSignatureIsValid(container.getSignatures().get(0), SignatureProfile.LT_TM);
	}

	@Test
	public void createAndValidateBDocTsContainer() throws Exception {
		Container container = createAndValidateContainer(SignatureProfile.LT, ContainerBuilder.BDOC_CONTAINER_TYPE, DigestAlgorithm.SHA512);
		assertSignatureIsValid(container.getSignatures().get(0), SignatureProfile.LT);
	}

	@Test
	public void validateExistingBDocContainer_withProductionConfiguration() throws Exception {
		Container container = ContainerBuilder.
				aContainer(BDOC_CONTAINER_TYPE).
				fromExistingFile(EXAMPLE_BDOC_CONTAINER_PATH).
				withConfiguration(new Configuration(Configuration.Mode.PROD)).
				build();
		ValidationResult result = container.validate();
		assertTrue(result.isValid());
	}

	@Test
	@Ignore("You need to add test certificates to the DDoc configuration to create test DDoc containers")
	public void createAndValidateDDocContainer() throws Exception {
		Container container = createAndValidateContainer(null, ContainerBuilder.DDOC_CONTAINER_TYPE, DigestAlgorithm.SHA1);
		Signature signature = container.getSignatures().get(0);
		assertNotNull(signature.getProducedAt());
		assertNotNull(signature.getClaimedSigningTime());
		assertTrue(signature.validateSignature().isValid());
	}

	private Container createAndValidateContainer(SignatureProfile signatureProfile, String containerType, DigestAlgorithm digestAlgorithm) throws IOException {
		Container container = createContainer(containerType);
		Signature signature = createSignature(signatureProfile, digestAlgorithm, container);
		container.addSignature(signature);
		assertTrue(signature.validateSignature().isValid());
		container.saveAsFile(testFolder.newFile("test-container2.bdoc").getPath());
		assertSignatureParameters(signature);
		return container;
	}

	private Container createContainer(String containerType) {
		return ContainerBuilder.
				aContainer(containerType).
				withConfiguration(configuration).
				withDataFile(testFile, MimeType.TEXT.getMimeTypeString()).
				build();
	}

	private Signature createSignature(SignatureProfile signatureProfile, DigestAlgorithm digestAlgorithm, Container container) {
		return SignatureBuilder.
					aSignature(container).
					withCity("Tallinn").
					withStateOrProvince("Harjumaa").
					withPostalCode("13456").
					withCountry("Estonia").
					withRoles("Suspicious Fisherman").
					withSignatureDigestAlgorithm(digestAlgorithm).
					withSignatureProfile(signatureProfile).
					withSignatureToken(testSignatureToken).
					invokeSigning();
	}

	private void assertSignatureParameters(Signature signature) {
		assertEquals("Tallinn", signature.getCity());
		assertEquals("Harjumaa", signature.getStateOrProvince());
		assertEquals("13456", signature.getPostalCode());
		assertEquals("Estonia", signature.getCountryName());
		assertEquals(1, signature.getSignerRoles().size());
		assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(0));
	}

	private void assertSignatureIsValid(Signature signature, SignatureProfile signatureProfile) {
		assertNotNull(signature.getProducedAt());
		assertEquals(signatureProfile, signature.getProfile());
		assertNotNull(signature.getClaimedSigningTime());
		assertNotNull(signature.getAdESSignature());
		assertTrue(signature.getAdESSignature().length > 1);
		assertTrue(signature.validateSignature().isValid());
	}

	private File createTestFile() throws IOException {
		File file = testFolder.newFile("test.txt");
		FileUtils.writeStringToFile(file, "This is a test file");
		return file;
	}
}
