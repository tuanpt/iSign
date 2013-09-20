package ooxml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import android.util.Log;

public class OOXMLSigner extends AbstractOOXMLSignatureService {

    private OOXMLTestDataStorage temporaryDataStorage = new OOXMLTestDataStorage();
    private ByteArrayOutputStream signedOOXMLOutputStream = new ByteArrayOutputStream();
    private byte[] ooxmlData;

    public byte[] signOOXMLFile(byte[] fileData, PrivateKey privateKey, Certificate[] certificateChain)
            throws Exception {
        this.ooxmlData = fileData;
        List<X509Certificate> certs = new LinkedList<X509Certificate>();
        Log.i("certs", "1");
        DigestInfo digestInfo = preSign(null, null);
        Log.i("certs", "2");
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initSign(privateKey);
        Log.i("certs", "3");
        sign.update(digestInfo.digestValue);
        Log.i("certs", "4");
        byte[] signatureValue = sign.sign();
        Log.i("certs", "5");
        return signOOXMLFile(signatureValue, certificateChain);
    }

    public byte[] signOOXMLFile(byte[] signatureValue, Certificate[] certificateChain)
            throws Exception {
        X509Certificate[] signingcertChain = new X509Certificate[certificateChain.length];
        Log.i("signOOXML","1");
        for (int i = 0; i < certificateChain.length; i++) {
            signingcertChain[i] = ((X509Certificate) certificateChain[i]);
        }
        postSign(signatureValue, Arrays.asList(signingcertChain));
        byte[] signedOOXMLData = getSignedOfficeOpenXMLDocumentData();
        return signedOOXMLData;
    }

    protected OutputStream getSignedOfficeOpenXMLDocumentOutputStream() {
        return this.signedOOXMLOutputStream;
    }

    protected InputStream getOfficeOpenXMLDocumentInputStream() {
        byte[] buff = new byte[this.ooxmlData.length];
        System.arraycopy(this.ooxmlData, 0, buff, 0, this.ooxmlData.length);
        return new ByteArrayInputStream(buff);
    }

    protected TemporaryDataStorage getTemporaryDataStorage() {
        return this.temporaryDataStorage;
    }

    public byte[] getSignedOfficeOpenXMLDocumentData() {
        return this.signedOOXMLOutputStream.toByteArray();
    }

    public void setOoxmlData(byte[] ooxmlData) {
        this.ooxmlData = ooxmlData;
    }

    static {
        OOXMLProvider.install();
    }
}