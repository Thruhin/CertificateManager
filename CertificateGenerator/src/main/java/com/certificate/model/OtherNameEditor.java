package com.certificate.model;

import java.beans.PropertyEditorSupport;
import java.io.IOException;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class OtherNameEditor extends PropertyEditorSupport{
	
	@Override
	  public String getAsText() {
	    if (this.getValue() == null) {
	      return null;
	    }
	    OtherName otherName = (OtherName) this.getValue();
	    return otherName.toString();
	  }

	  @Override
	  public void setAsText(String text) {
		
	    ObjectMapper mapper = new ObjectMapper();
	    OtherName otherName;
	    try {
	    	otherName = mapper.readValue(text, OtherName.class);
	      super.setValue(otherName);
	    } catch (IOException e) {
	      super.setValue(new OtherName());
	    }
	  }

}
