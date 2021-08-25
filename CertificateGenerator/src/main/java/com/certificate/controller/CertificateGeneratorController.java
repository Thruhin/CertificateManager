package com.certificate.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.certificate.enums.CertificateType;
import com.certificate.model.Certificate;
import com.certificate.model.CertificateSigningRequest;
import com.certificate.model.IssuerCertificateDetails;
import com.certificate.model.OtherName;
import com.certificate.service.CertificateProvider;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;

@RestController
@RequestMapping("/certificate")
public class CertificateGeneratorController {
	
	@Autowired
	private CertificateProvider certificateProvider;
	
	@Operation(description = "Returns all applications available in the tenant")
	@RequestMapping(value = "/root-ca", method = RequestMethod.POST)
	public Certificate generateZRootCertificate(
			@Parameter(description = "This is the common name thats required")
			@RequestParam(value="commonName", required=true)  String commonName,
			@RequestParam(value="country", required=true)  String country,
			@RequestParam(value="state", required=true)  String state,
			@RequestParam(value="location", required=true)  String location,
			@RequestParam(value="organization", required=true)  String organization,
			@RequestParam(value="validityInYears", required=true)  int validityInYears,
			@RequestParam(value="pathLength", required=true)  int pathLength) throws Exception {
		
		CertificateSigningRequest csr = new CertificateSigningRequest();
		csr.setCommonName(commonName);
		csr.setCountry(country);
		csr.setState(state);
		csr.setLocation(location);
		csr.setOrganization(organization);
		csr.setValidityInYears(validityInYears);
		csr.setPathLength(pathLength);
		return certificateProvider.generateCACertificate(csr, CertificateType.ROOT_CA);
	}
	
	@RequestMapping(value = "/intermediate-ca", method = RequestMethod.POST)
	public Certificate generateCaCertificate(
			@Parameter(description = "common name")
			@RequestParam(value="commonName", required=true)  String commonName,
			@RequestParam(value="country", required=true)  String country,
			@RequestParam(value="state", required=true)  String state,
			@RequestParam(value="location", required=true)  String location,
			@RequestParam(value="organization", required=true)  String organization,
			@RequestParam(value="validityInYears", required=true)  int validityInYears,
			@RequestParam(value="pathLength", required=true)   int pathLength,
			@RequestBody IssuerCertificateDetails issuerDetails) throws Exception {
		
		CertificateSigningRequest csr = new CertificateSigningRequest();
		csr.setCommonName(commonName);
		csr.setCountry(country);
		csr.setState(state);
		csr.setLocation(location);
		csr.setOrganization(organization);
		csr.setValidityInYears(validityInYears);
		csr.setIssuerPrivateKey(issuerDetails.getIssuerPrivateKey());
		csr.setIssuerPublicKey(issuerDetails.getIssuerPublicKey());
		csr.setX509Certificate(issuerDetails.getX509Certificate());
		return certificateProvider.generateCACertificate(csr, CertificateType.ROOT_CA);
	}
	
	
	@RequestMapping(value = "/server-certificate", method = RequestMethod.POST)
	public Certificate generateServerCertificate(@RequestParam(value="commonName", required=true)  String commonName,
			@RequestParam(value="country", required=true)  String country,
			@RequestParam(value="state", required=true)  String state,
			@RequestParam(value="location", required=true)  String location,
			@RequestParam(value="organization", required=true)  String organization,
			@RequestParam(value="validityInYears", required=true)  int validityInYears,
			@RequestParam(value="dnsNames", required=true) List<String> dnsName,
			@RequestBody IssuerCertificateDetails issuerDetails) throws Exception {
		
		CertificateSigningRequest csr = new CertificateSigningRequest();
		csr.setCommonName(commonName);
		csr.setCountry(country);
		csr.setState(state);
		csr.setLocation(location);
		csr.setOrganization(organization);
		csr.setValidityInYears(validityInYears);
		csr.setDnsName(dnsName);
		csr.setIssuerPrivateKey(issuerDetails.getIssuerPrivateKey());
		csr.setIssuerPublicKey(issuerDetails.getIssuerPublicKey());
		csr.setX509Certificate(issuerDetails.getX509Certificate());
		//System.out.println();
		return certificateProvider.generateCACertificate(csr, CertificateType.SERVER);
	}
	
	@RequestMapping(value = "/client-certificate", method = RequestMethod.POST)
	public Certificate generateClientCertificate(@RequestParam(value="commonName", required=true)  String commonName,
			@RequestParam(value="country", required=true)  String country,
			@RequestParam(value="state", required=true)  String state,
			@RequestParam(value="location", required=true)  String location,
			@RequestParam(value="organization", required=true)  String organization,
			@RequestParam(value="validityInYears", required=true)  int validityInYears,
			@RequestParam(value="otherNames", required=true) List<OtherName> otherNames,
			@RequestBody IssuerCertificateDetails issuerDetails) throws Exception {
		
		CertificateSigningRequest csr = new CertificateSigningRequest();
		csr.setCommonName(commonName);
		csr.setCountry(country);
		csr.setState(state);
		csr.setLocation(location);
		csr.setOrganization(organization);
		csr.setValidityInYears(validityInYears);
		csr.setOtherNames(otherNames);
		csr.setIssuerPrivateKey(issuerDetails.getIssuerPrivateKey());
		csr.setIssuerPublicKey(issuerDetails.getIssuerPublicKey());
		csr.setX509Certificate(issuerDetails.getX509Certificate());
		return certificateProvider.generateCACertificate(csr, CertificateType.CLIENT);
	}

}
