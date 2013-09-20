package ooxml;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.FilenameUtils;
import org.apache.xml.security.utils.Base64;
import org.apache.xpath.XPathAPI;
import org.jcp.xml.dsig.internal.dom.DOMReference;
import org.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import android.util.Log;

public abstract class AbstractXmlSignatureService
        implements SignatureService {

	@SuppressWarnings("unused")
	private static XMLDSigRI xmlDsigRI = null;
	@SuppressWarnings("unused")
	private static final String SIGNATURE_ID_ATTRIBUTE = "signature-id";
    private final List<SignatureAspect> signatureAspects;
    
    public AbstractXmlSignatureService() {
        this.signatureAspects = new LinkedList<SignatureAspect>();
    }
    
    protected void addSignatureAspect(SignatureAspect signatureAspect) {
        this.signatureAspects.add(signatureAspect);
    }

    public String getSignatureDigestAlgorithm() {
        return "SHA-1";
    }

    protected List<DigestInfo> getServiceDigestInfos() {
        return new LinkedList<DigestInfo>();
    }

    protected Document getEnvelopingDocument()
            throws ParserConfigurationException, IOException, SAXException {
        return null;
    }

    protected List<String> getReferenceUris() {
        return new LinkedList<String>();
    }

    protected List<ReferenceInfo> getReferences() {
        return new LinkedList<ReferenceInfo>();
    }

    protected URIDereferencer getURIDereferencer() {
        return null;
    }

    protected String getSignatureDescription() {
        return "XML Signature";
    }

    protected abstract TemporaryDataStorage getTemporaryDataStorage();

    protected abstract OutputStream getSignedDocumentOutputStream();

    public DigestInfo preSign(List<DigestInfo> digestInfos, List<X509Certificate> signingCertificateChain) throws NoSuchAlgorithmException {
        String digestAlgo = getSignatureDigestAlgorithm();
        Log.i("preSign","1");
        byte[] digestValue;        
        try {        	
        	Log.i("preSign","3");
            digestValue = getXmlSignatureDigestValue(digestAlgo, digestInfos);
            Log.i("preSign","4");
        } catch (Exception e) {
            throw new RuntimeException("XML signature error: " + e.getMessage(), e);
        }

        String description = getSignatureDescription();
        return new DigestInfo(digestValue, digestAlgo, description);
    }

    protected void postSign(Element sinatureElement, List<X509Certificate> signingCertificateChain) {
    }

    public void postSign(byte[] signatureValue, List<X509Certificate> signingCertificateChain) {
        TemporaryDataStorage temporaryDataStorage = getTemporaryDataStorage();
        InputStream documentInputStream = temporaryDataStorage.getTempInputStream();

        String signatureId = (String) temporaryDataStorage.getAttribute("signature-id");
        Document document;
        try {
            document = loadDocument(documentInputStream);
        } catch (Exception e) {
            throw new RuntimeException("DOM error: " + e.getMessage(), e);
        }

        Element nsElement = document.createElement("ns");
     
        nsElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
        Element signatureElement;
        try {
            signatureElement = (Element) XPathAPI.selectSingleNode(document, "//ds:Signature[@Id='" + signatureId + "']", nsElement);
        } catch (TransformerException e) {
            throw new RuntimeException("XPATH error: " + e.getMessage(), e);
        }
        if (null == signatureElement) {
            throw new RuntimeException("ds:Signature not found for @Id: " + signatureId);
        }

        NodeList signatureValueNodeList = signatureElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue");

        Element signatureValueElement = (Element) signatureValueNodeList.item(0);

        signatureValueElement.setTextContent(Base64.encode(signatureValue));

        postSign(signatureElement, signingCertificateChain);

        OutputStream signedDocumentOutputStream = getSignedDocumentOutputStream();

        if (null == signedDocumentOutputStream) {
            throw new IllegalArgumentException("signed document output stream is null");
        }
        try {
            writeDocument(document, signedDocumentOutputStream);
        } catch (Exception e) {
            throw new RuntimeException("error writing the signed XML document: " + e.getMessage(), e);
        }
    }

    protected String getCanonicalizationMethod() {
        return "http://www.w3.org/2001/10/xml-exc-c14n#";
    }

    public byte[] getXmlSignatureDigestValue(String digestAlgo, List<DigestInfo> digestInfos)
            throws ParserConfigurationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, TransformerFactoryConfigurationError, TransformerException, IOException, SAXException {
    	Log.i("getXMLSign","1");
        byte[] octets = getXmlSignatureDigestData(digestAlgo, digestInfos);
        Log.i("getXMLSign","2");
        return octets;
    }

    @SuppressWarnings("unchecked")
	public byte[] getXmlSignatureDigestData(String digestAlgo, List<DigestInfo> digestInfos)
            throws ParserConfigurationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, TransformerFactoryConfigurationError, TransformerException, IOException, SAXException {
        Document document = getEnvelopingDocument();
        Log.i("document","1");
        if (null == document) {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            Log.i("document","2");
            documentBuilderFactory.setNamespaceAware(true);
            Log.i("document","3");
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Log.i("document","4");
            document = documentBuilder.newDocument();
            Log.i("document","5");
        }

        Key key = new Key() {

            private static final long serialVersionUID = 1L;

            public String getAlgorithm() {
            	Log.i("key","1");
                return null;
            }

            public byte[] getEncoded() {
            	Log.i("key","2");
                return null;
            }

            public String getFormat() {
            	Log.i("key","3");
                return null;
            }
        };
        XMLSignContext xmlSignContext = new DOMSignContext(key, document);
        Log.i("xmlSignContext","1");
        Log.i("xmlSignContext","u");
        URIDereferencer uriDereferencer = null;
        Log.i("uri","u" + uriDereferencer);
//        if (null != uriDereferencer) {
//        	Log.i("uriDereferencer","1");
//            xmlSignContext.setURIDereferencer(uriDereferencer);
//            Log.i("uriDereferencer","2");
//        }

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
                "DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
        Log.i("signFactory","1");
        List<Reference> references = new LinkedList<Reference>();
        Log.i("signFactory","2");
        addDigestInfosAsReferences(digestInfos, signatureFactory, references);
        Log.i("signFactory","3");
        List<DigestInfo> serviceDigestInfos = getServiceDigestInfos();
        Log.i("signFactory","4");
        addDigestInfosAsReferences(serviceDigestInfos, signatureFactory, references);
        Log.i("signFactory","5");
        addReferenceIds(signatureFactory, xmlSignContext, references);
        Log.i("signFactory","6");
        addReferences(signatureFactory, references);
        Log.i("signFactory","7");

        String signatureId = "xmldsig-" + UUID.randomUUID().toString();
        List<XMLObject> objects = new LinkedList<XMLObject>();
        Log.i("OBJECTS","1");
        for (SignatureAspect signatureAspect : this.signatureAspects) {
            signatureAspect.preSign(signatureFactory, document, signatureId, references, objects);
            Log.i("signAspect","1");
        }

        SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(getSignatureMethod(digestAlgo), null);
        CanonicalizationMethod canonicalizationMethod = signatureFactory.newCanonicalizationMethod(getCanonicalizationMethod(), (C14NMethodParameterSpec) null);
        Log.i("canonicalizationMethod","1");
        SignedInfo signedInfo = signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, references);
        Log.i("signedInfo","1");
        String signatureValueId = signatureId + "-signature-value";
        XMLSignature xmlSignature = signatureFactory.newXMLSignature(signedInfo, null, objects, signatureId, signatureValueId);
//end :)
        DOMXMLSignature domXmlSignature = (DOMXMLSignature) xmlSignature;
        Log.i("domXmlSign","1");
        Node documentNode = document.getDocumentElement();
        if (null == documentNode) {
            documentNode = document;
        }
        String dsPrefix = null;

        domXmlSignature.marshal(documentNode, dsPrefix, (DOMCryptoContext) xmlSignContext);

        for (XMLObject object : objects) {
            List<XMLStructure> objectContentList = (List<XMLStructure>) object.getContent();
            for (XMLStructure objectContent : objectContentList) {
                if (false == objectContent instanceof Manifest) {
                    continue;
                }
                Manifest manifest = (Manifest) objectContent;
                List<Reference> manifestReferences = (List<Reference>) manifest.getReferences();
                for (Reference manifestReference : manifestReferences) {
                    if (null != manifestReference.getDigestValue()) {
                        continue;
                    }
                    DOMReference manifestDOMReference = (DOMReference) manifestReference;

                    manifestDOMReference.digest(xmlSignContext);
                }

            }

        }

        List<Reference> signedInfoReferences = (List<Reference>) signedInfo.getReferences();
        for (Reference signedInfoReference : signedInfoReferences) {
            DOMReference domReference = (DOMReference) signedInfoReference;
            if (null != domReference.getDigestValue()) {
                continue;
            }
            domReference.digest(xmlSignContext);
        }

        TemporaryDataStorage temporaryDataStorage = getTemporaryDataStorage();
        OutputStream tempDocumentOutputStream = temporaryDataStorage.getTempOutputStream();

        writeDocument(document, tempDocumentOutputStream);
        temporaryDataStorage.setAttribute("signature-id", signatureId);

        DOMSignedInfo domSignedInfo = (DOMSignedInfo) signedInfo;
        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
        domSignedInfo.canonicalize(xmlSignContext, dataStream);
        byte[] octets = dataStream.toByteArray();

        return octets;
    }

    private void addReferenceIds(XMLSignatureFactory signatureFactory, XMLSignContext xmlSignContext, List<Reference> references)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, XMLSignatureException {
        List<String> referenceUris = (List<String>) getReferenceUris();
        if (null == referenceUris) {
            return;
        }
        DigestMethod digestMethod = signatureFactory.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null);

        for (String referenceUri : referenceUris) {
            Reference reference = signatureFactory.newReference(referenceUri, digestMethod);

            references.add(reference);
        }
    }

    private void addReferences(XMLSignatureFactory xmlSignatureFactory, List<Reference> references)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        List<ReferenceInfo> referenceInfos = (List<ReferenceInfo>) getReferences();
        if (null == referenceInfos) {
            return;
        }
        if (referenceInfos.isEmpty()) {
            return;
        }
        DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null);

        for (ReferenceInfo referenceInfo : referenceInfos) {
            List<Transform> transforms = new LinkedList<Transform>();
            if (null != referenceInfo.getTransform()) {
                Transform transform = xmlSignatureFactory.newTransform(referenceInfo.getTransform(), (TransformParameterSpec) null);

                transforms.add(transform);
            }
            Reference reference = xmlSignatureFactory.newReference(referenceInfo.getUri(), digestMethod, transforms, null, null);

            references.add(reference);
        }
    }

    private void addDigestInfosAsReferences(List<DigestInfo> digestInfos, XMLSignatureFactory signatureFactory, List<Reference> references)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MalformedURLException {
        if (null == digestInfos) {
            return;
        }
        for (DigestInfo digestInfo : digestInfos) {
            byte[] documentDigestValue = digestInfo.digestValue;

            DigestMethod digestMethod = signatureFactory.newDigestMethod(getXmlDigestAlgo(digestInfo.digestAlgo), null);

            String uri = FilenameUtils.getName(new File(digestInfo.description).toURI().toURL().getFile());

            Reference reference = signatureFactory.newReference(uri, digestMethod, null, null, null, documentDigestValue);

            references.add(reference);
        }
    }

    private String getXmlDigestAlgo(String digestAlgo) {
        if ("SHA-1".equals(digestAlgo)) {
            return "http://www.w3.org/2000/09/xmldsig#sha1";
        }
        if ("SHA-256".equals(digestAlgo)) {
            return "http://www.w3.org/2001/04/xmlenc#sha256";
        }
        if ("SHA-512".equals(digestAlgo)) {
            return "http://www.w3.org/2001/04/xmlenc#sha512";
        }
        throw new RuntimeException("unsupported digest algo: " + digestAlgo);
    }

    private String getSignatureMethod(String digestAlgo) {
        if (null == digestAlgo) {
            throw new RuntimeException("digest algo is null");
        }
        if ("SHA-1".equals(digestAlgo)) {
            return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        }
        if ("SHA-256".equals(digestAlgo)) {
            return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        }
        if ("SHA-512".equals(digestAlgo)) {
            return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
        }
        if ("SHA-384".equals(digestAlgo)) {
            return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
        }
        if ("RIPEMD160".equals(digestAlgo)) {
            return "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";
        }
        throw new RuntimeException("unsupported sign algo: " + digestAlgo);
    }

    protected void writeDocument(Document document, OutputStream documentOutputStream)
            throws TransformerConfigurationException, TransformerFactoryConfigurationError, TransformerException, IOException {
        writeDocumentNoClosing(document, documentOutputStream);
        documentOutputStream.close();
    }

    protected void writeDocumentNoClosing(Document document, OutputStream documentOutputStream)
            throws TransformerConfigurationException, TransformerFactoryConfigurationError, TransformerException, IOException {
        writeDocumentNoClosing(document, documentOutputStream, false);
    }

    protected void writeDocumentNoClosing(Document document, OutputStream documentOutputStream, boolean omitXmlDeclaration)
            throws TransformerConfigurationException, TransformerFactoryConfigurationError, TransformerException, IOException {
        NoCloseOutputStream outputStream = new NoCloseOutputStream(documentOutputStream);

        Result result = new StreamResult(outputStream);
        Transformer xformer = TransformerFactory.newInstance().newTransformer();

        if (omitXmlDeclaration) {
            xformer.setOutputProperty("omit-xml-declaration", "yes");
        }
        Source source = new DOMSource(document);
        xformer.transform(source, result);
    }

    protected Document loadDocument(InputStream documentInputStream)
            throws ParserConfigurationException, SAXException, IOException {
        InputSource inputSource = new InputSource(documentInputStream);
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = documentBuilder.parse(inputSource);
        return document;
    }

    protected Document loadDocumentNoClose(InputStream documentInputStream)
            throws ParserConfigurationException, SAXException, IOException {
        NoCloseInputStream noCloseInputStream = new NoCloseInputStream(documentInputStream);

        InputSource inputSource = new InputSource(noCloseInputStream);
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = documentBuilder.parse(inputSource);
        return document;
    }

    public static class ReferenceInfo {

        private final String uri;
        private final String transform;

        public ReferenceInfo(String uri, String transform) {
            this.uri = uri;
            this.transform = transform;
        }

        public ReferenceInfo(String uri) {
            this(uri, null);
        }

        public String getUri() {
            return this.uri;
        }

        public String getTransform() {
            return this.transform;
        }
    }
}