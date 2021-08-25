package com.certificate.model;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class CertificateExtension {
	
	private ASN1ObjectIdentifier  extensionType;
    
    private Boolean isCritical;
    
    private ASN1Encodable extensionValue;
    
    public CertificateExtension(ASN1ObjectIdentifier extensionType ,Boolean isCritical , ASN1Encodable extensionValue) {
        this.extensionType = extensionType;
        this.isCritical = isCritical;
        this.extensionValue = extensionValue;
    }
    
    public ASN1ObjectIdentifier getExtensionType() {
		return extensionType;
	}

	public void setExtensionType(ASN1ObjectIdentifier extensionType) {
		this.extensionType = extensionType;
	}

	public Boolean getIsCritical() {
		return isCritical;
	}

	public void setIsCritical(Boolean isCritical) {
		this.isCritical = isCritical;
	}

	public ASN1Encodable getExtensionValue() {
		return extensionValue;
	}

	public void setExtensionValue(ASN1Encodable extensionValue) {
		this.extensionValue = extensionValue;
	}


}
