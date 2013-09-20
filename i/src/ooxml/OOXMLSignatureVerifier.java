package ooxml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackagePart;
import org.apache.poi.openxml4j.opc.PackagePartName;
import org.apache.poi.openxml4j.opc.PackageRelationship;
import org.apache.poi.openxml4j.opc.PackageRelationshipCollection;
import org.apache.poi.openxml4j.opc.PackagingURIHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class OOXMLSignatureVerifier extends SignatureVerifier {

    public static boolean isOOXML(InputStream ooxmlIn)
            throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(ooxmlIn);
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if ((false != "[Content_Types].xml".equals(zipEntry.getName()))
                    && (zipEntry.getSize() > 0L)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isSigned(byte[] fileData) throws Exception {
        InputStream ooxmlIn = new ByteArrayInputStream(fileData);
        List signatureParts = getSignatureParts(ooxmlIn);
        return !signatureParts.isEmpty();
    }

    public void verifyOOXMLSignature(BigInteger[] certSerialNumber, byte[] fileData) throws Exception {
        InputStream ooxmlIn = new ByteArrayInputStream(fileData);
        List<PackagePart> signatureParts = getSignatureParts(ooxmlIn);
        if (signatureParts.isEmpty()) {
//            throw IHTKKException.createException("IHTKK-0502", "Hồ sơ không có chữ ký điện tử");
        }
        if (signatureParts.size() < certSerialNumber.length) {
//            throw IHTKKException.createException("IHTKK-0502", "Hồ sơ không có đủ chữ ký điện tử (hồ sơ cần phải có ít nhất " + certSerialNumber.length + " chữ ký điện tử)");
        }
        OOXMLProvider.install();
        ooxmlIn.reset();
        for (PackagePart signaturePart : signatureParts) {
            Document signatureDocument = loadDocument(signaturePart);
            NodeList signatureNodeList = signatureDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            Node signatureNode = signatureNodeList.item(0);
            KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
            DOMValidateContext domValidateContext = new DOMValidateContext(keySelector, signatureNode);
            domValidateContext.setProperty("org.jcp.xml.dsig.validateManifests", Boolean.TRUE);

            OOXMLURIDereferencer dereferencer = new OOXMLURIDereferencer(ooxmlIn);
            domValidateContext.setURIDereferencer(dereferencer);

            XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();
            XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);

            if (!xmlSignature.validate(domValidateContext)) {
//                throw IHTKKException.createException("IHTKK-0502", "Chữ ký điện tử không đúng");
            }
            verifyCertificationChain(Calendar.getInstance().getTime(), certSerialNumber, keySelector.getCertChain());
        }
    }

    public static List<PackagePart> getSignatureParts(InputStream ooxmlIn) throws IOException, InvalidFormatException {
        List packageParts = new LinkedList();
        OPCPackage pkg = OPCPackage.open(ooxmlIn);
        PackageRelationshipCollection sigOrigRels = pkg.getRelationshipsByType("http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin");

        for (PackageRelationship rel : sigOrigRels) {
            PackagePartName relName = PackagingURIHelper.createPartName(rel.getTargetURI());

            PackagePart sigPart = pkg.getPart(relName);
            PackageRelationshipCollection sigRels = sigPart.getRelationshipsByType("http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature");

            for (PackageRelationship sigRel : sigRels) {
                PackagePartName sigRelName = PackagingURIHelper.createPartName(sigRel.getTargetURI());

                PackagePart sigRelPart = pkg.getPart(sigRelName);
                packageParts.add(sigRelPart);
            }
        }
        return packageParts;
    }

    private Document loadDocument(PackagePart part)
            throws ParserConfigurationException, SAXException, IOException {
        InputStream documentInputStream = part.getInputStream();
        return loadDocument(documentInputStream);
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
}