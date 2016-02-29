###Inwebo Outbound Provisioning Connector

The WSO2 Identity Server has the ability to provision users into different domains using its identity provisioning framework. Inwebo Outbound Provisioning Connector allows to provision the users into Inwebo API from WSO2 Identity Server.

###Build

mvn clean install

###Steps to run

1.  Build & copy the org.wso2.carbon.identity.provisioning.connector.inwebo-1.0.0.jar into <IS-HOME>/repository/components/dropins

2.  Copy the given resources/axis2_inwebo.xml into <IS-HOME>/repository/conf/axis2

3.  Follow the steps in https://docs.wso2.com/display/ISCONNECTORS/Configuring+Inwebo+Provisioning

###How You Can Contribute

You can create a third party connector and publish in WSO2 Connector Store.

https://docs.wso2.com/display/ISCONNECTORS/Creating+a+Third+Party+Authenticator+or+Connector+and+Publishing+in+WSO2+Store