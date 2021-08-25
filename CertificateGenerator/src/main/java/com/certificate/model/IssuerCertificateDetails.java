package com.certificate.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class IssuerCertificateDetails {
	
    private String issuerPrivateKey;
	
	private String issuerPublicKey;
	
	private String x509Certificate;
	
}
