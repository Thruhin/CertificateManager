package com.certificate.model;


import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CertificateSigningRequest {

	private String commonName;

	private String country;

	private String state;

	private String location;

	private String organization;

	private Integer validityInYears;

	private String issuerPrivateKey;

	private String issuerPublicKey;

	private String x509Certificate;

	private List<String> dnsName;

	private int pathLength;

	private List<OtherName> otherNames;

}
