/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.service.example;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.soap.Node;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.MessageContext.Scope;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.soap.SOAPFaultException;

/**
 *
 * @author orkhan.mirzayev
 */
public class DigestMessageHandler implements SOAPHandler<SOAPMessageContext> {

    private static final String WSSE_NS_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final QName QNAME_WSSE_USERNAMETOKEN = new QName(WSSE_NS_URI, "UsernameToken");
    private static final QName QNAME_WSSE_USERNAME = new QName(WSSE_NS_URI, "Username");
    private static final QName QNAME_WSSE_PASSWORD = new QName(WSSE_NS_URI, "Password");

    @Override
    public boolean handleMessage(SOAPMessageContext context) {

        System.out.println("Server : handleMessage()......");

        Boolean isRequest = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

        if(!isRequest){
            String wsseUsername = null;
            String wssePassword = null;
            try {
                SOAPMessage message = context.getMessage();
                message.writeTo(System.out);
                SOAPHeader header = context.getMessage().getSOAPHeader();
                Iterator<?> headerElements = header.examineAllHeaderElements();
                while (headerElements.hasNext()) {
                    SOAPHeaderElement headerElement = (SOAPHeaderElement) headerElements
                            .next();
                    if (headerElement.getElementName().getLocalName()
                            .equals("Security")) {
                        SOAPHeaderElement securityElement = headerElement;
                        Iterator<?> it2 = securityElement.getChildElements();
                        while (it2.hasNext()) {
                            Node soapNode = (Node) it2.next();
                            if (soapNode instanceof SOAPElement) {
                                SOAPElement element = (SOAPElement) soapNode;
                                QName elementQname = element.getElementQName();
                                if (QNAME_WSSE_USERNAMETOKEN.equals(elementQname)) {
                                    SOAPElement usernameTokenElement = element;
                                    wsseUsername = getFirstChildElementValue(usernameTokenElement, QNAME_WSSE_USERNAME);
                                    wssePassword = getFirstChildElementValue(usernameTokenElement, QNAME_WSSE_PASSWORD);
                                    break;
                                }
                            }

                            if (wsseUsername != null) {
                                break;
                            }
                        }
                    }
                    context.put("USERNAME", wsseUsername);
                    context.setScope("USERNAME", Scope.APPLICATION);

                    context.put("PASSWORD", wssePassword);
                    context.setScope("PASSWORD", Scope.APPLICATION);
                }
            } catch (Exception e) {
                System.out.println("Error reading SOAP message context: " + e);
                e.printStackTrace();
            }

        }
        //continue other handler chain
        return true;
    }

    private String getFirstChildElementValue(SOAPElement soapElement, QName qNameToFind) {
        String value = null;
        Iterator<?> it = soapElement.getChildElements(qNameToFind);
        while (it.hasNext()) {
            SOAPElement element = (SOAPElement) it.next(); //use first
            value = element.getValue();
        }
        return value;
    }

    @Override
    public boolean handleFault(SOAPMessageContext context) {

        System.out.println("Server : handleFault()......");

        return true;
    }

    @Override
    public void close(MessageContext context) {
        System.out.println("Server : close()......");
    }

    @Override
    public Set<QName> getHeaders() {
        final QName securityHeader = new QName(
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "Security",
                "wsse");
        final HashSet headers = new HashSet();
        headers.add(securityHeader);
        return headers;
    }

    private void generateSOAPErrMessage(SOAPMessage msg, String reason) {
        try {
            SOAPBody soapBody = msg.getSOAPPart().getEnvelope().getBody();
            SOAPFault soapFault = soapBody.addFault();
            soapFault.setFaultString(reason);
            throw new SOAPFaultException(soapFault);
        } catch (SOAPException e) {
        }
    }

}
