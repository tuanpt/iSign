package ooxml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class RelationshipTransformService extends TransformService {

    public static final String TRANSFORM_URI = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
    private final List<String> sourceIds;

    public RelationshipTransformService() {
        this.sourceIds = new LinkedList();
    }

    public void init(TransformParameterSpec params) throws InvalidAlgorithmParameterException {
        if (false == params instanceof RelationshipTransformParameterSpec) {
            throw new InvalidAlgorithmParameterException();
        }
        RelationshipTransformParameterSpec relParams = (RelationshipTransformParameterSpec) params;

        for (String sourceId : relParams.getSourceIds()) {
            this.sourceIds.add(sourceId);
        }
    }

    public void init(XMLStructure parent, XMLCryptoContext context) throws InvalidAlgorithmParameterException {
        DOMStructure domParent = (DOMStructure) parent;
        Node parentNode = domParent.getNode();
        Element nsElement = parentNode.getOwnerDocument().createElement("ns");
        nsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");

        nsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:mdssi", "http://schemas.openxmlformats.org/package/2006/digital-signature");
        NodeList nodeList;
        try {
            nodeList = XPathAPI.selectNodeList(parentNode, "mdssi:RelationshipReference/@SourceId", nsElement);
        } catch (TransformerException e) {
            throw new InvalidAlgorithmParameterException();
        }
        if (0 == nodeList.getLength());
        for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
            Node node = nodeList.item(nodeIdx);
            String sourceId = node.getTextContent();
            this.sourceIds.add(sourceId);
        }
    }

    public void marshalParams(XMLStructure parent, XMLCryptoContext context)
            throws MarshalException {
        DOMStructure domParent = (DOMStructure) parent;
        Node parentNode = domParent.getNode();
        Element parentElement = (Element) parentNode;
        parentElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:mdssi", "http://schemas.openxmlformats.org/package/2006/digital-signature");

        Document document = parentNode.getOwnerDocument();
        for (String sourceId : this.sourceIds) {
            Element relationshipReferenceElement = document.createElementNS("http://schemas.openxmlformats.org/package/2006/digital-signature", "mdssi:RelationshipReference");

            relationshipReferenceElement.setAttribute("SourceId", sourceId);
            parentElement.appendChild(relationshipReferenceElement);
        }
    }

    public AlgorithmParameterSpec getParameterSpec() {
        return null;
    }

    public Data transform(Data data, XMLCryptoContext context) throws TransformException {
        OctetStreamData octetStreamData = (OctetStreamData) data;
        InputStream octetStream = octetStreamData.getOctetStream();
        Document relationshipsDocument;
        try {
            relationshipsDocument = loadDocument(octetStream);
        } catch (Exception e) {
            throw new TransformException(e.getMessage(), e);
        }
        Element nsElement = relationshipsDocument.createElement("ns");
        nsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:tns", "http://schemas.openxmlformats.org/package/2006/relationships");

        Element relationshipsElement = relationshipsDocument.getDocumentElement();

        NodeList childNodes = relationshipsElement.getChildNodes();
        for (int nodeIdx = 0; nodeIdx < childNodes.getLength(); nodeIdx++) {
            Node childNode = childNodes.item(nodeIdx);
            if (1 != childNode.getNodeType()) {
                relationshipsElement.removeChild(childNode);
                nodeIdx--;
            } else {
                Element childElement = (Element) childNode;
                String idAttribute = childElement.getAttribute("Id");
                if (false == this.sourceIds.contains(idAttribute)) {
                    relationshipsElement.removeChild(childNode);
                    nodeIdx--;
                }

                if (null == childElement.getAttributeNode("TargetMode")) {
                    childElement.setAttribute("TargetMode", "Internal");
                }
            }
        }
        sortRelationshipElements(relationshipsElement);
        try {
            return toOctetStreamData(relationshipsDocument);
        } catch (TransformerException e) {
            throw new TransformException(e.getMessage(), e);

        }
    }

    private void sortRelationshipElements(Element relationshipsElement) {
        List<Element> relationshipElements = new LinkedList();
        NodeList relationshipNodes = relationshipsElement.getElementsByTagName("*");

        int nodeCount = relationshipNodes.getLength();
        for (int nodeIdx = 0; nodeIdx < nodeCount; nodeIdx++) {
            Node relationshipNode = relationshipNodes.item(0);
            Element relationshipElement = (Element) relationshipNode;
            relationshipElements.add(relationshipElement);
            relationshipsElement.removeChild(relationshipNode);
        }
        Collections.sort(relationshipElements, new RelationshipComparator());
        for (Element relationshipElement : relationshipElements) {
            relationshipsElement.appendChild(relationshipElement);
        }
    }

    private String toString(Node dom) throws TransformerException {
        Source source = new DOMSource(dom);
        StringWriter stringWriter = new StringWriter();
        Result result = new StreamResult(stringWriter);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();

        Transformer transformer = transformerFactory.newTransformer();

        transformer.setOutputProperty("omit-xml-declaration", "yes");
        transformer.transform(source, result);
        return stringWriter.getBuffer().toString();
    }

    private OctetStreamData toOctetStreamData(Node node) throws TransformerException {
        Source source = new DOMSource(node);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Result result = new StreamResult(outputStream);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();

        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty("omit-xml-declaration", "yes");
        transformer.transform(source, result);
        return new OctetStreamData(new ByteArrayInputStream(outputStream.toByteArray()));
    }

    private Document loadDocument(InputStream documentInputStream)
            throws ParserConfigurationException, SAXException, IOException {
        InputSource inputSource = new InputSource(documentInputStream);
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = documentBuilder.parse(inputSource);
        return document;
    }

    public Data transform(Data data, XMLCryptoContext context, OutputStream os) throws TransformException {
        return null;
    }

    public boolean isFeatureSupported(String feature) {
        return false;
    }
}