package com.swisscom.saml.sp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Privat on 4/7/14.
 */
public class SPConstants {
    public static final String SP_ENTITY_ID = "EJPDTestSP";
    public static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/SAMLAuth/SAMLAssertionConsumer";
    public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
    public static final String GOTO_URL_SESSION_ATTRIBUTE = "gotoURL";
}
