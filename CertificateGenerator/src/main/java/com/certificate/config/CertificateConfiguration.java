package com.certificate.config;

import java.beans.PropertyEditor;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.config.CustomEditorConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.certificate.model.OtherName;
import com.certificate.model.OtherNameEditor;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class CertificateConfiguration {
	
	@Bean
    public KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        return keyPairGenerator;
    }

	@Bean
	public JcaContentSignerBuilder getContentSignerBuilder() {
		return new JcaContentSignerBuilder("SHA256withRSA");

	}

	@Bean
	public JcaX509ExtensionUtils getExtensionUtils() throws NoSuchAlgorithmException {
		return new JcaX509ExtensionUtils();
	}
	
//	@Bean
//	  public GroupedOpenApi groupedOpenApi() {
//	    return GroupedOpenApi.builder().group("v1").pathsToMatch("/**").packagesToScan("com.certificate.*").build();
//	  }

	  @Bean
	  public OpenAPI openAPI() {
	    OpenAPI openAPI = new OpenAPI();
	    openAPI.info(new Info().title("SAP Edge Services Policy Service")
	        .description("Provides APIs for managing the life cycle and configuration of edge services").version("1.0.0"));
	    return openAPI;
	  }
	  
	  @Bean
	    public static CustomEditorConfigurer customEditorConfigurer() {
	        Map<Class<?>, Class<? extends PropertyEditor>> customEditors = new HashMap<>();
	        customEditors.put(OtherName.class, OtherNameEditor.class);
	        CustomEditorConfigurer configurer = new CustomEditorConfigurer();
	        configurer.setCustomEditors(customEditors);
	        return configurer;
	    }
	
}
