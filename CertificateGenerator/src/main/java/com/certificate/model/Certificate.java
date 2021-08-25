package com.certificate.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Certificate {
	
	public Certificate(String id, String caCert, String publicKey, String privateKey, String trustStore, String keyStore){
		this.id = id;
		this.caCert = caCert;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.trustStore = trustStore;
		this.keyStore = keyStore;
	}
	
	private String id;
	private String caCert;
	private String publicKey;
	private String privateKey;
	private String trustStore;
	private String keyStore;

}
