package com.certificate.service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.certificate.enums.CertificateType;
import com.certificate.model.Certificate;
import com.certificate.model.CertificateExtension;
import com.certificate.model.CertificateSigningRequest;
import com.certificate.model.OtherName;
import com.certificate.utils.CertificateUtils;
import com.certificate.utils.Constants;

@Service
public class BouncyCastleCertificateProviderImpl implements CertificateProvider {

	@Autowired
	private KeyPairGenerator keyPairGenerator;

	@Autowired
	private JcaContentSignerBuilder contentSignerBuilder;
	
	@Autowired
    private JcaX509ExtensionUtils certExtUtils;

	@Override
	public Certificate generateCACertificate(CertificateSigningRequest csr, CertificateType certificateType) throws Exception {

		try {
			// Generate KeyPair for the certificate
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			// Build the certificate subject
			// CN=Test CA, C=IN, ST=Karnataka, L=Bangalore, O=Google
			X500Name certificateSubject = new X500Name(
					"CN=" + csr.getCommonName() + " , C=" + csr.getCountry() + ", ST=" + csr.getState() + ", L="+ csr.getLocation()+", O=" + csr.getOrganization());
			
			// Set the validity based on the input given
			Calendar calendar = Calendar.getInstance();
			Date validFrom = calendar.getTime();
			calendar.add(Calendar.YEAR, csr.getValidityInYears());
			Date validTo = calendar.getTime();

			//generate a serial number for the certificate
			Random random = new Random();
			BigInteger certificateSerialNum = new BigInteger(3, random);
						
			// Get subject of the issuer certificate. In case root certificate, use the same subject as of root
            X500Name issuerCertificateSubject = csr.getX509Certificate() != null
                ? new JcaX509CertificateHolder(CertificateUtils.convertPEMcertToX509Cert(csr.getX509Certificate())).getSubject() : certificateSubject; 
                
                
			// Returns the issuer public key. Incase of Root certificate , its own public
			// key becomes issuer private key(self signed)
			PublicKey issuerPublicKey = StringUtils.isEmpty(csr.getIssuerPublicKey()) ? keyPair.getPublic(): CertificateUtils.convertStringToPublicKey(csr.getIssuerPublicKey());
			
			// Returns the issuer private key. Incase of Root certificate , its own private
			// key becomes issuer private key(self signed)
			PrivateKey issuerPrivateKey = StringUtils.isEmpty(csr.getIssuerPrivateKey()) ? keyPair.getPrivate() : CertificateUtils.convertStringToPrivateKey(csr.getIssuerPrivateKey()); 
			
			
			//Step 1:  CSR request builder
			//   --> Build CertificateRequestBuilder using a subject provided and issuer Public Key. In case of root certificate, the same public key would be used
			PKCS10CertificationRequestBuilder p10CertificateRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
					certificateSubject, issuerPublicKey);

			//Step 2: Content Signer
			// Build the request with the CA's private key. Incase of self signed, the private key would be the same
			ContentSigner csrContentSigner = contentSignerBuilder.build(issuerPrivateKey);

			//Step 3: Content Signing Request
			// --> build a CSR Request through the content signer that had been created with CA's public and private key
			PKCS10CertificationRequest contentSigningRequest = p10CertificateRequestBuilder.build(csrContentSigner);

			//Step 4: Create a certificate builder using the 
			// certificate subject,
			// serial number
			// valiDFrom
			// validTO
			// Issuer subject
			// Issuer Public key info
			X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuerCertificateSubject,
					certificateSerialNum, validFrom, validTo, contentSigningRequest.getSubject(),
					contentSigningRequest.getSubjectPublicKeyInfo());
			
			//Step 5: Extensions vary based on the Certificate type
			//ROOT Certificate: 
			List<CertificateExtension> extensions = new ArrayList<>();
			
			buildExtensions(extensions, csr, issuerPublicKey, issuerPrivateKey, keyPair, certificateType);

			extensions.stream().forEach(extension -> {
				try {
					certificateBuilder.addExtension(extension.getExtensionType(), extension.getIsCritical(),
							extension.getExtensionValue());
				} catch (CertIOException e) {
					throw new RuntimeException(e.getMessage());
				}
			});

			// build the certificate
			X509CertificateHolder certificateHolder = certificateBuilder.build(csrContentSigner);
			X509Certificate x509Certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

			String caCert = CertificateUtils.convertObjectToPEMString(x509Certificate);
			String privateKeyPem = CertificateUtils.convertObjectToPEMString(keyPair.getPrivate());
			String publicKeyPem = CertificateUtils.convertObjectToPEMString(keyPair.getPublic());
			String trustStore = "";
			String keyStore = "";
			
			return new Certificate(certificateSerialNum.toString(), caCert, publicKeyPem, privateKeyPem, trustStore, keyStore);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} 
	}
	
	private void buildExtensions(List<CertificateExtension> extentions,
	        CertificateSigningRequest csr, PublicKey issuerPublicKey, PrivateKey issuerPrivateKey,
	        KeyPair keyPair, CertificateType certificateType) throws Exception
	       {

	        switch (certificateType) {
	            case ROOT_CA: 
	            case INTERMEDIATE_CA: {
	                addCentralAuthorityExtensions(extentions, csr.getPathLength());
	                break;
	            }
	            case SERVER: {
	                addServerCertificateExtensions(extentions, csr);
	                break;
	            }
	            case CLIENT: {
	                addClientCertificateExtensions(extentions, csr, issuerPrivateKey);
	                break;
	            }
	            default:
	                throw new Exception("Invalid Certificate type");
	        }
	        addKeyIdentifierExtensions(extentions, issuerPublicKey, keyPair.getPublic());
	    }
	
	
	private void addCentralAuthorityExtensions(List<CertificateExtension> extentions, int pathlength) {
		CertificateExtension certificateExtension = new CertificateExtension(Extension.basicConstraints, true,
				new BasicConstraints(pathlength));
		extentions.add(certificateExtension);
		certificateExtension = new CertificateExtension(Extension.keyUsage, true,
				new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
		extentions.add(certificateExtension);

	}
	
	private void addServerCertificateExtensions(List<CertificateExtension> extentions,
			CertificateSigningRequest certificateMetaData) {
		CertificateExtension certificateExtension = new CertificateExtension(Extension.keyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
		extentions.add(certificateExtension);
		certificateExtension = new CertificateExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		extentions.add(certificateExtension);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
				new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth });
		certificateExtension = new CertificateExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
		extentions.add(certificateExtension);

		// Add SAN extentions when DNS Names is not null or empty
		if (!CollectionUtils.isEmpty(certificateMetaData.getDnsName())) {
			List<GeneralName> generalNames = new ArrayList<>();
			certificateMetaData.getDnsName().stream()
					.forEach(dnsName -> generalNames.add(new GeneralName(GeneralName.dNSName, dnsName)));
			GeneralNames subjectAlternativeNames = new GeneralNames(generalNames.toArray(new GeneralName[] {}));
			certificateExtension = new CertificateExtension(Extension.subjectAlternativeName, false,
					subjectAlternativeNames);
			extentions.add(certificateExtension);
		}
	}
	
	private void addClientCertificateExtensions(List<CertificateExtension> extentions,
			CertificateSigningRequest certificateMetaData, PrivateKey issuerPrivateKey) throws Exception {
		CertificateExtension certificateExtension = new CertificateExtension(Extension.keyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature));
		extentions.add(certificateExtension);
		certificateExtension = new CertificateExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		extentions.add(certificateExtension);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth });
		certificateExtension = new CertificateExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
		extentions.add(certificateExtension);
		addOtherNameExtensions(extentions, certificateMetaData, issuerPrivateKey);

	}
	
	private void addOtherNameExtensions(List<CertificateExtension> extentions, CertificateSigningRequest certificateMetaData,
			PrivateKey issuerPrivateKey) throws Exception {
		String otherName = null;
		
		for(OtherName otherNameInfo : certificateMetaData.getOtherNames()) {
			String value = otherNameInfo.isSigned() ? CertificateUtils.signWithPrivateKey(otherNameInfo.getValue(), issuerPrivateKey) : otherNameInfo.getValue();
			if(StringUtils.isEmpty(otherName)) {
				otherName = StringUtils.join(otherNameInfo.getKey(),":",value);
			} else {
				otherName = StringUtils.join("|",otherNameInfo.getKey(),":",value);
			}
		}
		
		ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(Constants.EXTENDED_CERTIFICATE_ATTRIBUTES_OID);
		CertificateExtension certificateExtension = new CertificateExtension(Extension.subjectAlternativeName, false,
				new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(
						new ASN1Encodable[] { oid, new DERTaggedObject(0, new DERUTF8String(otherName)) }))));
		extentions.add(certificateExtension);
	}
	
	private void addKeyIdentifierExtensions(List<CertificateExtension> extentions, PublicKey issuerPublicKey,
			PublicKey publicKey) {
		CertificateExtension certificateExtension = new CertificateExtension(Extension.subjectKeyIdentifier, false,
				certExtUtils.createSubjectKeyIdentifier(publicKey));
		extentions.add(certificateExtension);
		certificateExtension = new CertificateExtension(Extension.authorityKeyIdentifier, false,
				certExtUtils.createAuthorityKeyIdentifier(issuerPublicKey));
		extentions.add(certificateExtension);
	}

}
