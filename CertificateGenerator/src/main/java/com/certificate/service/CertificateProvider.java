package com.certificate.service;

import com.certificate.enums.CertificateType;
import com.certificate.model.Certificate;
import com.certificate.model.CertificateSigningRequest;

public interface CertificateProvider {
	
	public Certificate generateCACertificate(CertificateSigningRequest csr, CertificateType certificateType) throws Exception;

}
