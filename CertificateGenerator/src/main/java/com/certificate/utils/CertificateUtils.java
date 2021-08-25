package com.certificate.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class CertificateUtils {
	
	public static String convertObjectToPEMString(Object obj) throws IOException {

		StringWriter stringWriter = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(obj);
		}
		return stringWriter.toString();

	}

	public static String signWithPrivateKey(String str, PrivateKey privateKey) throws Exception {
		Signature signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHMN);
		signature.initSign(privateKey);
		byte[] raw = str.getBytes("UTF-8");
		signature.update(raw);
		byte[] signed = signature.sign();
		return Base64.getEncoder().encodeToString(signed);
	}
	
	
	public static PublicKey convertStringToPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		StringReader keyReader = new StringReader(publicKey);
		PEMParser pemParser = new PEMParser(keyReader);
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
        return (PublicKey) converter.getPublicKey(publicKeyInfo);
	}
	
	public static PrivateKey convertStringToPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		StringReader keyReader = new StringReader(privateKey);
		PEMParser pemParser = new PEMParser(keyReader);
		Object object = pemParser.readObject();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		KeyPair keyPair;
		PEMKeyPair pemKeyPair = (PEMKeyPair) object;
		keyPair = converter.getKeyPair(pemKeyPair);
		pemParser.close();
		return keyPair.getPrivate();
	}
	
	public static X509Certificate convertPEMcertToX509Cert(String certificate) throws Exception {
        InputStream certificateStream = new ByteArrayInputStream(certificate.getBytes());
        return (X509Certificate) CertificateFactory
            .getInstance(Constants.CERTIFICATE_TYPE_X)
            .generateCertificate(certificateStream);
    }

}
