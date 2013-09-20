package ooxml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.xpath.XPathAPI;

import org.jcp.xml.dsig.internal.dom.DOMKeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import android.util.Log;



public abstract class AbstractOOXMLSignatureService extends AbstractXmlSignatureService {

    protected AbstractOOXMLSignatureService() {
        addSignatureAspect(new OOXMLSignatureAspect(this));
    }

    protected String getSignatureDescription() {
        return "Office OpenXML Document";
    }

    public String getFilesDigestAlgorithm() {
        return null;
    }

    protected final URIDereferencer getURIDereferencer() {
        return new OOXMLURIDereferencer(getOfficeOpenXMLDocumentInputStream());
    }

    protected String getCanonicalizationMethod() {
        return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    }

    protected void postSign(Element signatureElement, List<X509Certificate> signingCertificateChain) {
        NodeList objectNodeList = signatureElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Object");
        Node nextSibling;
        if (0 == objectNodeList.getLength()) {
            nextSibling = null;
        } else {
            nextSibling = objectNodeList.item(0);
        }
        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
        List<X509Certificate> x509DataObjects = new LinkedList<X509Certificate>();

        X509Certificate signingCertificate = (X509Certificate) signingCertificateChain.get(0);
        KeyValue keyValue;
        try {
            keyValue = keyInfoFactory.newKeyValue(signingCertificate.getPublicKey());
        } catch (KeyException e) {
            throw new RuntimeException("key exception: " + e.getMessage(), e);
        }

        for (X509Certificate certificate : signingCertificateChain) {
            x509DataObjects.add(certificate);
        }
        X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
        List<XMLStructure> keyInfoContent = new LinkedList<XMLStructure>();
        keyInfoContent.add(keyValue);
        keyInfoContent.add(x509Data);
        Log.i("keyinfo","1");
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(keyInfoContent);
        Log.i("keyinfo","2");
        DOMKeyInfo domKeyInfo = (DOMKeyInfo) keyInfo;
        Log.i("keyinfo","3");
        Key key = new Key() {

            private static final long serialVersionUID = 1L;

            public String getAlgorithm() {
                return null;
            }

            public byte[] getEncoded() {
                return null;
            }

            public String getFormat() {
                return null;
            }
        };
        XMLSignContext xmlSignContext = new DOMSignContext(key, signatureElement);

        DOMCryptoContext domCryptoContext = (DOMCryptoContext) xmlSignContext;
        String dsPrefix = null;
        try {
            domKeyInfo.marshal(signatureElement, nextSibling, dsPrefix, domCryptoContext);
        } catch (MarshalException e) {
            throw new RuntimeException("marshall error: " + e.getMessage(), e);
        }
    }

    protected abstract OutputStream getSignedOfficeOpenXMLDocumentOutputStream();

    protected abstract InputStream getOfficeOpenXMLDocumentInputStream();

    private void outputSignedOfficeOpenXMLDocument(byte[] signatureData)
            throws IOException, ParserConfigurationException, SAXException, TransformerException {
        OutputStream signedOOXMLOutputStream = getSignedOfficeOpenXMLDocumentOutputStream();

        if (null == signedOOXMLOutputStream) {
            throw new NullPointerException("signedOOXMLOutputStream is null");
        }

        String signatureZipEntryName = "_xmlsignatures/sig-" + UUID.randomUUID().toString() + ".xml";

        ZipOutputStream zipOutputStream = copyOOXMLContent(signatureZipEntryName, signedOOXMLOutputStream);

        ZipEntry zipEntry = new ZipEntry(signatureZipEntryName);
        zipOutputStream.putNextEntry(zipEntry);
        IOUtils.write(signatureData, zipOutputStream);
        zipOutputStream.close();
    }

    private ZipOutputStream copyOOXMLContent(String signatureZipEntryName, OutputStream signedOOXMLOutputStream)
            throws IOException, ParserConfigurationException, SAXException, TransformerConfigurationException, TransformerFactoryConfigurationError, TransformerException {
        ZipOutputStream zipOutputStream = new ZipOutputStream(signedOOXMLOutputStream);

        ZipInputStream zipInputStream = new ZipInputStream(getOfficeOpenXMLDocumentInputStream());

        boolean hasOriginSigsRels = false;
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            ZipEntry newZipEntry = new ZipEntry(zipEntry.getName());
            zipOutputStream.putNextEntry(newZipEntry);
            if ("[Content_Types].xml".equals(zipEntry.getName())) {
                Document contentTypesDocument = loadDocumentNoClose(zipInputStream);

                Element typesElement = contentTypesDocument.getDocumentElement();

                Element overrideElement = contentTypesDocument.createElementNS("http://schemas.openxmlformats.org/package/2006/content-types", "Override");

                overrideElement.setAttribute("PartName", "/" + signatureZipEntryName);

                overrideElement.setAttribute("ContentType", "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml");

                typesElement.appendChild(overrideElement);

                Element nsElement = contentTypesDocument.createElement("ns");
                nsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:tns", "http://schemas.openxmlformats.org/package/2006/content-types");

                NodeList nodeList = XPathAPI.selectNodeList(contentTypesDocument, "/tns:Types/tns:Default[@Extension='sigs']", nsElement);

                if (0 == nodeList.getLength()) {
                    Element defaultElement = contentTypesDocument.createElementNS("http://schemas.openxmlformats.org/package/2006/content-types", "Default");

                    defaultElement.setAttribute("Extension", "sigs");
                    defaultElement.setAttribute("ContentType", "application/vnd.openxmlformats-package.digital-signature-origin");

                    typesElement.appendChild(defaultElement);
                }

                writeDocumentNoClosing(contentTypesDocument, zipOutputStream, false);
            } else if ("_rels/.rels".equals(zipEntry.getName())) {
                Document relsDocument = loadDocumentNoClose(zipInputStream);

                Element nsElement = relsDocument.createElement("ns");
                nsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:tns", "http://schemas.openxmlformats.org/package/2006/relationships");

                NodeList nodeList = XPathAPI.selectNodeList(relsDocument, "/tns:Relationships/tns:Relationship[@Target='_xmlsignatures/origin.sigs']", nsElement);

                if (0 == nodeList.getLength()) {
                    Element relationshipElement = relsDocument.createElementNS("http://schemas.openxmlformats.org/package/2006/relationships", "Relationship");

                    relationshipElement.setAttribute("Id", "rel-id-" + UUID.randomUUID().toString());

                    relationshipElement.setAttribute("Type", "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin");

                    relationshipElement.setAttribute("Target", "_xmlsignatures/origin.sigs");

                    relsDocument.getDocumentElement().appendChild(relationshipElement);
                }

                writeDocumentNoClosing(relsDocument, zipOutputStream, false);
            } else if ("_xmlsignatures/_rels/origin.sigs.rels".equals(zipEntry.getName())) {
                hasOriginSigsRels = true;
                Document originSignRelsDocument = loadDocumentNoClose(zipInputStream);

                Element relationshipElement = originSignRelsDocument.createElementNS("http://schemas.openxmlformats.org/package/2006/relationships", "Relationship");

                String relationshipId = "rel-" + UUID.randomUUID().toString();
                relationshipElement.setAttribute("Id", relationshipId);
                relationshipElement.setAttribute("Type", "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature");

                String target = FilenameUtils.getName(signatureZipEntryName);
                relationshipElement.setAttribute("Target", target);
                originSignRelsDocument.getDocumentElement().appendChild(relationshipElement);

                writeDocumentNoClosing(originSignRelsDocument, zipOutputStream, false);
            } else {
                IOUtils.copy(zipInputStream, zipOutputStream);
            }
        }

        if (false == hasOriginSigsRels) {
            addOriginSigsRels(signatureZipEntryName, zipOutputStream);
            addOriginSigs(zipOutputStream);
        }

        zipInputStream.close();
        return zipOutputStream;
    }

    private void addOriginSigs(ZipOutputStream zipOutputStream) throws IOException {
        zipOutputStream.putNextEntry(new ZipEntry("_xmlsignatures/origin.sigs"));
    }

    private void addOriginSigsRels(String signatureZipEntryName, ZipOutputStream zipOutputStream)
            throws ParserConfigurationException, IOException, TransformerConfigurationException, TransformerFactoryConfigurationError, TransformerException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        Document originSignRelsDocument = documentBuilder.newDocument();

        Element relationshipsElement = originSignRelsDocument.createElementNS("http://schemas.openxmlformats.org/package/2006/relationships", "Relationships");

        relationshipsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "http://schemas.openxmlformats.org/package/2006/relationships");

        originSignRelsDocument.appendChild(relationshipsElement);

        Element relationshipElement = originSignRelsDocument.createElementNS("http://schemas.openxmlformats.org/package/2006/relationships", "Relationship");

        String relationshipId = "rel-" + UUID.randomUUID().toString();
        relationshipElement.setAttribute("Id", relationshipId);
        relationshipElement.setAttribute("Type", "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature");

        String target = FilenameUtils.getName(signatureZipEntryName);
        relationshipElement.setAttribute("Target", target);
        relationshipsElement.appendChild(relationshipElement);

        zipOutputStream.putNextEntry(new ZipEntry("_xmlsignatures/_rels/origin.sigs.rels"));
        writeDocumentNoClosing(originSignRelsDocument, zipOutputStream, false);
    }

    protected OutputStream getSignedDocumentOutputStream() {
        OutputStream signedDocumentOutputStream = new OOXMLSignedDocumentOutputStream();

        return signedDocumentOutputStream;
    }

    private class OOXMLSignedDocumentOutputStream extends ByteArrayOutputStream {

        private OOXMLSignedDocumentOutputStream() {
        }

        public void close()
                throws IOException {
            super.close();
            try {
                AbstractOOXMLSignatureService.this.outputSignedOfficeOpenXMLDocument(toByteArray());
            } catch (Exception e) {
                throw new IOException("generic error: " + e.getMessage());
            }
        }
    }
}