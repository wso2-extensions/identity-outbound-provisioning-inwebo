/*
 * Copyright (c) 2015-2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.provisioning.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPPart;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;

public class InweboUserManager {
    private static final Log log = LogFactory.getLog(InweboUserManager.class);

    /**
     * Set the client certificate to Default SSL Context
     *
     * @param certificateFile File containing certificate (PKCS12 format)
     * @param certPassword    Password of certificate
     * @throws Exception
     */
    public static void setHttpsClientCert(String certificateFile, String certPassword)  throws KeyStoreException,
            NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        if (certificateFile == null || !new File(certificateFile).exists()) {
            return;
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        InputStream keyInput = new FileInputStream(certificateFile);
        keyStore.load(keyInput, certPassword.toCharArray());
        keyInput.close();
        keyManagerFactory.init(keyStore, certPassword.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        SSLContext.setDefault(context);
    }

    /**
     * Method to create SOAP connection
     */
    public static String invokeSOAP(InweboUser user, String operation) throws IdentityProvisioningException {
        String provisionedId = null;
        SOAPConnectionFactory soapConnectionFactory = null;
        SOAPConnection soapConnection = null;
        try {
            Properties inweboProperties = new Properties();
            String resourceName = InweboConnectorConstants.PROPERTIES_FILE;
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            InputStream resourceStream = loader.getResourceAsStream(resourceName);
            try {
                inweboProperties.load(resourceStream);
            } catch (IOException e) {
                log.error("Unable to load the properties file", e);
                throw new IdentityProvisioningException("Unable to load the properties file", e);
            }

            SOAPMessage soapMessage = null;
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
            soapConnection = soapConnectionFactory.createConnection();
            String url = inweboProperties.getProperty(InweboConnectorConstants.INWEBO_URL);
            if (operation.equals(InweboConnectorConstants.INWEBO_OPERATION_POST)) {
                soapMessage = createUserSOAPMessage(inweboProperties, user);
            } else if (operation.equals(InweboConnectorConstants.INWEBO_OPERATION_PUT)) {
                soapMessage = updateUserSOAPMessage(inweboProperties, user);
            } else if (operation.equals(InweboConnectorConstants.INWEBO_OPERATION_DELETE)) {
                soapMessage = deleteUserSOAPMessage(inweboProperties, user.getLoginId(), user.getUserId(), user.getServiceId());
            }
            SOAPMessage soapResponse = soapConnection.call(soapMessage, url);
            if (operation.equals(InweboConnectorConstants.INWEBO_OPERATION_POST)) {
                if (soapResponse.getSOAPBody().getElementsByTagName("id").getLength() != 0) {
                    provisionedId = soapResponse.getSOAPBody().getElementsByTagName("id").item(0).getTextContent().toString();
                    if (StringUtils.isEmpty(provisionedId) || "0".equals(provisionedId)) {
                        String error = soapResponse.getSOAPBody().getElementsByTagName("loginCreateReturn").item(0)
                                .getTextContent().toString();
                        throw new IdentityProvisioningException("Error occurred while creating the user in InWebo:" + error);
                    }
                } else {
                    throw new IdentityProvisioningException("Unable to find the provisioning ID");
                }
            } else if (operation.equals(InweboConnectorConstants.INWEBO_OPERATION_PUT)) {
                if (soapResponse.getSOAPBody().getElementsByTagName("loginUpdateReturn").getLength() != 0) {
                    String updationStatus = soapResponse.getSOAPBody().getElementsByTagName("loginUpdateReturn").item(0)
                            .getTextContent().toString();
                    boolean processStatus = StringUtils.equals("OK", updationStatus);
                    if (!processStatus) {
                        String error = soapResponse.getSOAPBody().getElementsByTagName("loginUpdateReturn").item(0)
                                .getTextContent().toString();
                        throw new IdentityProvisioningException("Error occurred while updating the user in InWebo:" + error);
                    }
                } else {
                    throw new IdentityProvisioningException("Unable to get the updation status");
                }
            } else if (operation.equals(InweboConnectorConstants.INWEBO_OPERATION_DELETE)) {
                if (soapResponse.getSOAPBody().getElementsByTagName("loginDeleteReturn").getLength() != 0) {
                    String deletionStatus = soapResponse.getSOAPBody().getElementsByTagName("loginDeleteReturn").item(0)
                            .getTextContent().toString();
                    boolean processStatus = StringUtils.equals("OK", deletionStatus);
                    if (!processStatus) {
                        String error = soapResponse.getSOAPBody().getElementsByTagName("loginDeleteReturn").item(0)
                                .getTextContent().toString();
                        throw new IdentityProvisioningException("Error occurred while deleting the user from InWebo:"
                                + error);
                    }
                } else {
                    throw new IdentityProvisioningException("Unable to get the operation status");
                }
            }
        } catch (SOAPException e) {
            throw new IdentityProvisioningException("Error occurred while sending SOAP Request to Server", e);
        } finally {
            try {
                if (soapConnection != null) {
                    soapConnection.close();
                }
            } catch (SOAPException e) {
                log.error("Error while closing the SOAP connection", e);
            }
        }
        return provisionedId;
    }

    private static SOAPMessage createUserSOAPMessage(Properties inweboProperties, InweboUser user) throws SOAPException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = inweboProperties.getProperty(InweboConnectorConstants.INWEBO_URI);
        SOAPEnvelope envelope = soapPart.getEnvelope();
        String namespacePrefix = InweboConnectorConstants.SOAPMessage.SOAP_NAMESPACE_PREFIX;
        envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem =
                soapBody.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_ACTION_LOGIN_CREATE, namespacePrefix);
        SOAPElement soapBodyElem1 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_USER_ID, namespacePrefix);
        soapBodyElem1.addTextNode(user.getUserId());
        SOAPElement soapBodyElem2 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_SERVICE_ID, namespacePrefix);
        soapBodyElem2.addTextNode(user.getServiceId());
        SOAPElement soapBodyElem3 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_LOGIN, namespacePrefix);
        soapBodyElem3.addTextNode(user.getLogin());
        SOAPElement soapBodyElem4 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_FIRST_NAME, namespacePrefix);
        soapBodyElem4.addTextNode(user.getFirstName());
        SOAPElement soapBodyElem5 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_NAME, namespacePrefix);
        soapBodyElem5.addTextNode(user.getLastName());
        SOAPElement soapBodyElem6 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_MAIL, namespacePrefix);
        soapBodyElem6.addTextNode(user.getMail());
        SOAPElement soapBodyElem7 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_PHONE, namespacePrefix);
        soapBodyElem7.addTextNode(user.getPhone());
        SOAPElement soapBodyElem8 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_STATUS, namespacePrefix);
        soapBodyElem8.addTextNode(user.getStatus());
        SOAPElement soapBodyElem9 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_ROLE, namespacePrefix);
        soapBodyElem9.addTextNode(user.getRole());
        SOAPElement soapBodyElem10 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_ACCESS, namespacePrefix);
        soapBodyElem10.addTextNode(user.getAccess());
        SOAPElement soapBodyElem11 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_CONTENT_TYPE, namespacePrefix);
        soapBodyElem11.addTextNode(user.getCodeType());
        SOAPElement soapBodyElem12 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_LANG, namespacePrefix);
        soapBodyElem12.addTextNode(user.getLanguage());
        SOAPElement soapBodyElem13 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_EXTRA_FIELDS, namespacePrefix);
        soapBodyElem13.addTextNode(user.getExtraFields());
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader(InweboConnectorConstants.SOAPMessage.SOAP_ACTION, serverURI
                + InweboConnectorConstants.SOAPMessage.SOAP_ACTION_HEADER);
        soapMessage.saveChanges();
        return soapMessage;
    }

    private static SOAPMessage updateUserSOAPMessage(Properties inweboProperties, InweboUser user) throws SOAPException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = inweboProperties.getProperty(InweboConnectorConstants.INWEBO_URI);
        SOAPEnvelope envelope = soapPart.getEnvelope();
        String namespacePrefix = InweboConnectorConstants.SOAPMessage.SOAP_NAMESPACE_PREFIX;
        envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem =
                soapBody.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_ACTION_LOGIN_UPDATE, namespacePrefix);
        SOAPElement soapBodyElem1 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_USER_ID, namespacePrefix);
        soapBodyElem1.addTextNode(user.getUserId());
        SOAPElement soapBodyElem2 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_SERVICE_ID, namespacePrefix);
        soapBodyElem2.addTextNode(user.getServiceId());
        SOAPElement soapBodyElem3 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_LOGIN_ID, namespacePrefix);
        soapBodyElem3.addTextNode(user.getLoginId());
        SOAPElement soapBodyElem4 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_LOGIN, namespacePrefix);
        soapBodyElem4.addTextNode(user.getLogin());
        SOAPElement soapBodyElem5 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_FIRST_NAME, namespacePrefix);
        soapBodyElem5.addTextNode(user.getFirstName());
        SOAPElement soapBodyElem6 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_NAME, namespacePrefix);
        soapBodyElem6.addTextNode(user.getLastName());
        SOAPElement soapBodyElem7 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_MAIL, namespacePrefix);
        soapBodyElem7.addTextNode(user.getMail());
        SOAPElement soapBodyElem8 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_PHONE, namespacePrefix);
        soapBodyElem8.addTextNode(user.getPhone());
        SOAPElement soapBodyElem9 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_STATUS, namespacePrefix);
        soapBodyElem9.addTextNode(user.getStatus());
        SOAPElement soapBodyElem10 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_ROLE, namespacePrefix);
        soapBodyElem10.addTextNode(user.getRole());
        SOAPElement soapBodyElem11 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_EXTRA_FIELDS, namespacePrefix);
        soapBodyElem11.addTextNode(user.getExtraFields());
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader(InweboConnectorConstants.SOAPMessage.SOAP_ACTION, serverURI
                + InweboConnectorConstants.SOAPMessage.SOAP_ACTION_HEADER);
        soapMessage.saveChanges();
        return soapMessage;
    }

    private static SOAPMessage deleteUserSOAPMessage(Properties inweboProperties, String loginId, String userId,
                                                     String serviceId) throws SOAPException {

        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = inweboProperties.getProperty(InweboConnectorConstants.INWEBO_URI);
        SOAPEnvelope envelope = soapPart.getEnvelope();
        String namespacePrefix = InweboConnectorConstants.SOAPMessage.SOAP_NAMESPACE_PREFIX;
        envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem =
                soapBody.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_ACTION_LOGIN_DELETE, namespacePrefix);
        SOAPElement soapBodyElem1 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_USER_ID, namespacePrefix);
        soapBodyElem1.addTextNode(userId);
        SOAPElement soapBodyElem2 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_SERVICE_ID, namespacePrefix);
        soapBodyElem2.addTextNode(serviceId);
        SOAPElement soapBodyElem3 =
                soapBodyElem.addChildElement(InweboConnectorConstants.SOAPMessage.SOAP_LOGIN_ID, namespacePrefix);
        soapBodyElem3.addTextNode(loginId);
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader(InweboConnectorConstants.SOAPMessage.SOAP_ACTION, serverURI
                + InweboConnectorConstants.SOAPMessage.SOAP_ACTION_HEADER);
        soapMessage.saveChanges();
        return soapMessage;
    }
}
