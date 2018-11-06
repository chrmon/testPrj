package com.swisscom.saml.sp;

import java.io.IOException;
import java.io.StringWriter;
import java.security.Provider;
import java.security.Security;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.swisscom.saml.OpenSAMLUtils;
import com.swisscom.saml.idp.IDPConstants;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Servlet implementation class SAMLServlet
 */
public class SAMLServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(SAMLServlet.class);

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public SAMLServlet() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see Servlet#init(ServletConfig)
	 */
	public void init(ServletConfig config) throws ServletException {

		JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		try {
			javaCryptoValidationInitializer.init();
		} catch (InitializationException e) {
			e.printStackTrace();
		}

		for (Provider jceProvider : Security.getProviders()) {
			logger.info(jceProvider.getInfo());
		}

		try {
			logger.info("Initializing");
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException("Initialization failed");
		}
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		// response.getWriter().append("Served at: ").append(request.getContextPath());
		// TODO Auto-generated method stub
		try {
			InitializationService.initialize();
		} catch (InitializationException ie) {
			// TODO: handle exception
			ie.printStackTrace();
		}

		redirectUserForAuthentication(response);

		/*
		 * // AuthnRequest AuthnRequest authnRequest = buildAuthnRequest();
		 * 
		 * // create SML AuthRequest MessageContext context = new MessageContext();
		 * context.setMessage(authnRequest); HTTPPostEncoder encoder = new
		 * HTTPPostEncoder(); encoder.setMessageContext(context);
		 * encoder.setHttpServletResponse(response); try { encoder.initialize(); } catch
		 * (ComponentInitializationException e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); } try { encoder.encode(); } catch
		 * (MessageEncodingException e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); } System.out.println("momento ");
		 */

	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

	/**
	 * @param httpServletResponse
	 */
	private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
		AuthnRequest authnRequest = buildAuthnRequest();
		redirectUserWithRequest(httpServletResponse, authnRequest);

	}

	/**
	 * @param httpServletResponse
	 * @param authnRequest
	 */
	private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {

		MessageContext context = new MessageContext();
		context.setMessage(authnRequest);
		context.getSubcontext(SAMLBindingContext.class, true).setRelayState("HereMyRelayState");

		SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
		SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
		endpointContext.setEndpoint(getIPDEndpoint());

		// Get a velocity engine for the HTTP-POST binding (building of an HTML
		// document)
		org.apache.velocity.app.VelocityEngine velocityEngine = net.shibboleth.utilities.java.support.velocity.VelocityEngine
				.newVelocityEngine();
		HTTPPostEncoder encoder = new HTTPPostEncoder();
		encoder.setVelocityEngine(velocityEngine);
		encoder.setVelocityTemplateId("saml2-post-binding2.vm");
		encoder.setMessageContext(context);
		encoder.setHttpServletResponse(httpServletResponse);

		try {
			encoder.initialize();
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		}

		logger.info("AuthnRequest: ");
		logSAMLObject(authnRequest);

		logger.info("Redirecting to IDP");
		try {
			encoder.encode();
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * @return
	 */
	private AuthnRequest buildAuthnRequest() {
		AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setDestination(getIPDSSODestination());
		// authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
		authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
		authnRequest.setIssuer(buildIssuer());
		authnRequest.setNameIDPolicy(buildNameIdPolicy());
		authnRequest.setForceAuthn(false);
		authnRequest.setIsPassive(false);
		// authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

		Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
		signature.setSigningCredential(SPCredentials.getCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		// add key info und public key
		X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
		kiFactory.setEmitEntityCertificate(true);
		KeyInfo keyInfo = null;
		try {
			keyInfo = kiFactory.newInstance().generate(SPCredentials.getCredential());
		} catch (SecurityException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		signature.setKeyInfo(keyInfo);

		authnRequest.setSignature(signature);

		try {
			XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
		} catch (MarshallingException e1) {
			e1.printStackTrace();
		}

		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return authnRequest;
	}

	/**
	 * @return
	 */
	private String getIPDSSODestination() {
		return IDPConstants.SSO_SERVICE;
	}

	/**
	 * @return
	 */
	private Issuer buildIssuer() {
		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(getSPIssuerValue());

		return issuer;
	}

	/**
	 * @return
	 */
	private String getSPIssuerValue() {
		return SPConstants.SP_ENTITY_ID;
	}

	/**
	 * @return
	 */
	private NameIDPolicy buildNameIdPolicy() {
		NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
		nameIDPolicy.setAllowCreate(true);

		nameIDPolicy.setFormat(NameIDType.UNSPECIFIED);

		return nameIDPolicy;
	}

	/**
	 * @return
	 */
	private String getAssertionConsumerEndpoint() {
		return SPConstants.ASSERTION_CONSUMER_SERVICE;
	}

	/**
	 * @return
	 */
	private RequestedAuthnContext buildRequestedAuthnContext() {
		RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

		AuthnContextClassRef x509AuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
		x509AuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

		requestedAuthnContext.getAuthnContextClassRefs().add(x509AuthnContextClassRef);

		return requestedAuthnContext;

	}

	/**
	 * @return
	 */
	private Endpoint getIPDEndpoint() {
		SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(getIPDSSODestination());

		return endpoint;
	}

	/**
	 * @param object
	 */
	public static void logSAMLObject(final XMLObject object) {
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
				&& object.getDOM() != null) {
			element = object.getDOM();
		} else {
			try {
				Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
				out.marshall(object);
				element = object.getDOM();

			} catch (MarshallingException e) {
				logger.error(e.getMessage(), e);
			}
		}

		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(element);

			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();

			logger.info(xmlString);
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	}

}
