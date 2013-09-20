package ooxml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import utils.Base64Utils;
//import javax.swing.JOptionPane;

public class SignatureVerifier {

    protected static final String X509_CERTIFICATE_TYPE = "X.509";
    protected static final String CERT_CHAIN_ENCODING = "PkiPath";
    protected static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
    protected static final String CERT_CHAIN_VALIDATION_ALGORITHM = "PKIX";
    protected X509Certificate[] rootCerts;
    protected X509Certificate[] trustedCerts;
    protected HashMap crlMap;

    public void verifyFileSignsture(byte[] fileData, String signature, String certChain, BigInteger[] certSerialNumber)
            throws Exception {
        if ((signature == null) || (signature.length() == 0)) {
//            JOptionPane.showMessageDialog(null, "Hồ sơ không có chữ ký điện tử");
        }
        verifyFileSignature(certSerialNumber, fileData, signature, certChain);
    }

    public void verifyFileSignature(BigInteger[] certSerialNumber, byte[] doc, String signatureBase64Encoded, String certChainBase64Encoded)
            throws Exception {
        byte[] signature = Base64Utils.base64Decode(signatureBase64Encoded);
        CertPath certPath = loadCertPathFromBase64String(certChainBase64Encoded);
        List certsInChain = certPath.getCertificates();
        X509Certificate[] certChain = (X509Certificate[]) (X509Certificate[]) certsInChain.toArray(new X509Certificate[0]);
        X509Certificate cert = certChain[0];

        if (!verifyDocumentSignature(doc, cert, signature)) {
//            JOptionPane.showMessageDialog(null, "Chữ ký điện tử không đúng");
        }
        verifyCertificationChain(new Date(), certSerialNumber, certChain);
    }

    public boolean verifyDocumentSignature(byte[] aDocument, PublicKey aPublicKey, byte[] aSignature)
            throws GeneralSecurityException {
        Signature signatureAlgorithm = Signature.getInstance("SHA1withRSA");
        signatureAlgorithm.initVerify(aPublicKey);
        signatureAlgorithm.update(aDocument);
        boolean valid = signatureAlgorithm.verify(aSignature);
        return valid;
    }

    public boolean verifyDocumentSignature(byte[] aDocument, X509Certificate aCertificate, byte[] aSignature)
            throws GeneralSecurityException {
        PublicKey publicKey = aCertificate.getPublicKey();
        boolean valid = verifyDocumentSignature(aDocument, publicKey, aSignature);
        return valid;
    }

    public boolean checkRevokedFromCrlFile(X509Certificate cert) throws CertificateException, FileNotFoundException, CRLException {
        String issuerDN = cert.getIssuerDN().getName();
        X509CRL crl = (X509CRL) this.crlMap.get(issuerDN);
        if (null == crl) {
            return false;
        }
        return crl.isRevoked(cert);
    }

    public void verifyCertificationChain(Date dValidity, BigInteger[] certSerialNumber, X509Certificate[] certChain) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate cert = null;
        for (int i = 0; i < certSerialNumber.length; i++) {
            if (certSerialNumber[i].equals(certChain[0].getSerialNumber())) {
                cert = certChain[0];
                break;
            }
        }
        if (cert == null) {
//            JOptionPane.showMessageDialog(null, "Chứng thư số chưa được đăng ký với cơ quan Thuế");
        }
        try {
            cert.checkValidity(dValidity);
        } catch (CertificateExpiredException ex) {
//            JOptionPane.showMessageDialog(null, "Chứng thư số đã hết hạn");
        } catch (CertificateNotYetValidException ex) {
//            JOptionPane.showMessageDialog(null, "Chứng thư số chưa có hiệu lực");
        }

        if (checkRevokedFromCrlFile(cert)) {
//            JOptionPane.showMessageDialog(null, "Chứng thư số đã bị thu hồi");
        }

        if (certChain.length < 2) {
            verifyCertificate(cert);
            return;
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certFactory.generateCertPath(Arrays.asList(certChain));
        try {
            HashSet trustAnchors = new HashSet();
            for (int i = 0; i < this.rootCerts.length; i++) {
                TrustAnchor trustAnchor = new TrustAnchor(this.rootCerts[i], null);
                trustAnchors.add(trustAnchor);
            }

            PKIXParameters certPathValidatorParams = new PKIXParameters(trustAnchors);
            certPathValidatorParams.setRevocationEnabled(false);
            CertPathValidator chainValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), new BouncyCastleProvider());

            CertPath certChainForValidation = removeLastCertFromCertChain(certPath);
            try {
                chainValidator.validate(certChainForValidation, certPathValidatorParams);
            } catch (CertPathValidatorException certPathEx) {
                certPathEx.printStackTrace();
            }
        } catch (GeneralSecurityException ex) {
            ex.printStackTrace();
//            JOptionPane.showMessageDialog(null, "Chứng thư số không hợp pháp");
        }
    }

    public void verifyCertificate(X509Certificate aCertificate) throws Exception {
        for (int i = 0; i < this.trustedCerts.length; i++) {
            X509Certificate trustedCert = this.trustedCerts[i];
            try {
                aCertificate.verify(trustedCert.getPublicKey());
                return;
            } catch (GeneralSecurityException ex) {
            }

        }

//        JOptionPane.showMessageDialog(null, "Chứng thư số không hợp pháp");
    }

    private CertPath removeLastCertFromCertChain(CertPath aCertChain)
            throws CertificateException {
        List certs = aCertChain.getCertificates();
        int certsCount = certs.size();
        List certsWithoutLast = certs.subList(0, certsCount - 1);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certChainWithoutLastCert = cf.generateCertPath(certsWithoutLast);
        return certChainWithoutLastCert;
    }

    public static CertPath loadCertPathFromBase64String(String aCertChainBase64Encoded) throws CertificateException, IOException {
        byte[] certChainEncoded = Base64Utils.base64Decode(aCertChainBase64Encoded);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream certChainStream = new ByteArrayInputStream(certChainEncoded);
        CertPath certPath;
        try {
            certPath = cf.generateCertPath(certChainStream, "PkiPath");
        } finally {
            certChainStream.close();
        }
        return certPath;
    }

    public static X509Certificate loadX509CertificateFromStream(InputStream aCertStream)
            throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(aCertStream);
        return cert;
    }

    public static X509Certificate[] getCertificateList(String certDirPath)
            throws IOException, GeneralSecurityException {
        File dir = new File(certDirPath);
        File[] fList = dir.listFiles();
        int count = fList.length;

        ArrayList certArr = new ArrayList();

        for (int i = 0; i < count; i++) {
            File rootCertFile = fList[i];
            if (!rootCertFile.isDirectory()) {
                InputStream certStream = new FileInputStream(rootCertFile);
                try {
                    X509Certificate trustedCertificate = loadX509CertificateFromStream(certStream);
                    certArr.add(trustedCertificate);
                } catch (CertificateException certEx) {
                    certEx.printStackTrace();
                } finally {
                    certStream.close();
                }
            }
        }
        return (X509Certificate[]) (X509Certificate[]) certArr.toArray(new X509Certificate[0]);
    }

    public X509Certificate loadX509CertificateFromCERFile(String aFileName)
            throws GeneralSecurityException, IOException {
        FileInputStream fis = new FileInputStream(aFileName);
        X509Certificate cert = null;
        try {
            cert = loadX509CertificateFromStream(fis);
        } finally {
            fis.close();
        }
        return cert;
    }

    public void setTrustedCerts(X509Certificate[] trustedCerts) {
        this.trustedCerts = trustedCerts;
    }

    public void setRootCerts(X509Certificate[] rootCerts) {
        this.rootCerts = rootCerts;
    }

    public void setCrlMap(HashMap crlMap) {
        this.crlMap = crlMap;
    }
}