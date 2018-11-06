package com.swisscom.saml;

import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Scrapbook {

	private static Logger LOGGER = LoggerFactory.getLogger(Scrapbook.class.getName());


	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			InitializationService.initialize();
			Scrapbook sb = new Scrapbook();
			sb.createAuthRequest();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}

	/*
	 * create AuthnRequest s. OPENSAML Book
	 */
	private String createAuthRequest() throws Exception {
		AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setDestination(getIPDDestination());
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
		authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());

		NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
		nameIDPolicy.setFormat(NameIDType.UNSPECIFIED);
		nameIDPolicy.setAllowCreate(true);
		authnRequest.setNameIDPolicy(nameIDPolicy);

		// create SML AuthRequest
		MessageContext context = new MessageContext();
		context.setMessage(authnRequest);
		HTTPPostEncoder encoder = new HTTPPostEncoder();
		encoder.setMessageContext(context);
		encoder.setHttpServletResponse(null);
		encoder.initialize();
		encoder.encode();

		return "ok";
	}

	private String getIPDDestination() {
		return "IdP URL";
	}

	private String getAssertionConsumerEndpoint() {
		return "Assertion Consumer Endpoint";
	}

}
