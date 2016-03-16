/*
 *  Copyright (c) 2015-2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.provisioning.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.ProvisionedIdentifier;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;

import java.util.Properties;

public class InweboProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final Log log = LogFactory.getLog(InweboProvisioningConnector.class);
    private InweboProvisioningConnectorConfig configHolder;

    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName())) {
                    if ("1".equals(property.getValue())) {
                        jitProvisioningEnabled = true;
                    }
                }
            }
        }
        configHolder = new InweboProvisioningConnectorConfig(configs);
    }

    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {
        try {
            String provisionedId = null;
            if (provisioningEntity != null) {
                String p12file = configHolder.getValue(InweboConnectorConstants.INWEBO_P12FILE);
                String p12password = configHolder.getValue(InweboConnectorConstants.INWEBO_P12PASSWORD);
                String userId = configHolder.getValue(InweboConnectorConstants.INWEBO_USER_ID);
                String serviceId = configHolder.getValue(InweboConnectorConstants.INWEBO_SERVICE_ID);
                String status = configHolder.getValue(InweboConnectorConstants.INWEBO_STATUS);
                String role = configHolder.getValue(InweboConnectorConstants.INWEBO_ROLE);
                String extraFields = StringUtils.isNotEmpty(configHolder.getValue(InweboConnectorConstants.INWEBO_EXTRAFIELDS))
                        ? configHolder.getValue(InweboConnectorConstants.INWEBO_EXTRAFIELDS) : "";

                String firstNameClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.ConnectorClaims.FIRST_NAME_CLAIM,
                                InweboConnectorConstants.ConnectorClaims.IDP_CLAIM_URI_FIRSTNAME,
                                (String) null, false)).get(0);
                String lastNameClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.ConnectorClaims.LAST_NAME_CLAIM,
                                InweboConnectorConstants.ConnectorClaims.IDP_CLAIM_URI_LARSTNAME,
                                (String) null, false)).get(0);
                String emailClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.ConnectorClaims.MAIL_CLAIM,
                                InweboConnectorConstants.ConnectorClaims.IDP_CLAIM_URI_EMAIL,
                                (String) null, false)).get(0);
                String phoneClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.ConnectorClaims.PHONE_CLAIM,
                                InweboConnectorConstants.ConnectorClaims.IDP_CLAIM_URI_PHONE,
                                (String) null, false)).get(0);
                if (StringUtils.isEmpty(firstNameClaim) || StringUtils.isEmpty(lastNameClaim)
                        || StringUtils.isEmpty(emailClaim) || StringUtils.isEmpty(phoneClaim)) {
                    log.error("Claims are not set properly.");
                    throw new IdentityProvisioningException("Claims are not set properly.");
                }
                if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("JIT provisioning disabled for inwebo connector");
                    }
                    return null;
                }
                if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                    InweboUser user = new InweboUser();
                    user.setFirstName(firstNameClaim);
                    user.setLastName(lastNameClaim);
                    user.setUserId(userId);
                    user.setServiceId(serviceId);
                    user.setMail(emailClaim);
                    user.setPhone(phoneClaim);
                    user.setStatus(status);
                    user.setRole(role);
                    user.setExtraFields(extraFields);
                    System.setProperty(InweboConnectorConstants.AXIS2, InweboConnectorConstants.AXIS2_FILE);
                    if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                        String access = configHolder.getValue(InweboConnectorConstants.INWEBO_ACCESS);
                        String codeType = configHolder.getValue(InweboConnectorConstants.INWEBO_CODETYPE);
                        String languageClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.ConnectorClaims.LANGUAGE_CLAIM,
                                        InweboConnectorConstants.ConnectorClaims.IDP_CLAIM_URI_LANGUAGE,
                                        (String) null, false)).get(0);
                        String login = provisioningEntity.getEntityName().toString();
                        user.setAccess(access);
                        user.setCodeType(codeType);
                        user.setLanguage(languageClaim);
                        user.setLogin(login);
                        provisionedId = createUser(user, p12file, p12password);
                    } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                        String loginFromClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.ConnectorClaims.USERNAME_CLAIM, null,
                                        (String) null, false)).get(0);
                        if (StringUtils.isEmpty(loginFromClaim)) {
                            log.error("Unable to get the username from claim.");
                            throw new IdentityProvisioningException("Unable to get the username from claim.");
                        }
                        String loginId = provisioningEntity.getIdentifier().getIdentifier();
                        user.setLogin(loginFromClaim);
                        user.setLoginId(loginId);
                        updateUser(user, p12file, p12password);
                    } else if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                        deleteUser(provisioningEntity, serviceId, userId, p12file, p12password);
                    } else {
                        throw new IdentityProvisioningException("Unsupported provisioning opertaion.");
                    }
                }
            }
            // creates a provisioned identifier for the provisioned user.
            ProvisionedIdentifier identifier = new ProvisionedIdentifier();
            if (StringUtils.isNotEmpty(provisionedId) && !"0".equals(provisionedId)) {
                identifier.setIdentifier(provisionedId);
            }
            return identifier;
        } catch (IdentityProvisioningException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private String createUser(InweboUser user, String p12file, String p12password)
            throws IdentityProvisioningException {
        String provisionedId = null;
        try {
            InweboUserManager.setHttpsClientCert(p12file, p12password);
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException
                | UnrecoverableKeyException | KeyManagementException | IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while adding certificate: " + e.getMessage(), e);
        }
        try {
            InweboUserManager userManager = new InweboUserManager();
            provisionedId = userManager.invokeSOAP(user, InweboConnectorConstants.INWEBO_OPERATION_POST);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while creating the user in InWebo: " + e.getMessage(), e);
        }
        return provisionedId;
    }

    private void updateUser(InweboUser user, String p12file, String p12password)
            throws IdentityProvisioningException {
        try {
            InweboUserManager.setHttpsClientCert(p12file, p12password);
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException
                | UnrecoverableKeyException | KeyManagementException | IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while adding certificate: " + e.getMessage(), e);
        }
        try {
            InweboUserManager userManager = new InweboUserManager();
            userManager.invokeSOAP(user, InweboConnectorConstants.INWEBO_OPERATION_PUT);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while updating the user: " + e.getMessage(), e);
        }
    }

    private void deleteUser(ProvisioningEntity provisioningEntity, String serviceId, String userId, String p12file,
                            String p12password) throws IdentityProvisioningException {
        try {
            InweboUserManager.setHttpsClientCert(p12file, p12password);
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException
                | UnrecoverableKeyException | KeyManagementException | IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while adding certificate: " + e.getMessage(), e);
        }
        try {
            String loginId = provisioningEntity.getIdentifier().getIdentifier();
            InweboUser user = new InweboUser();
            user.setLoginId(loginId);
            user.setUserId(userId);
            user.setServiceId(serviceId);
            InweboUserManager userManager = new InweboUserManager();
            userManager.invokeSOAP(user, InweboConnectorConstants.INWEBO_OPERATION_DELETE);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while deleting the user from Inwebo: " + e.getMessage(), e);
        }
    }
}