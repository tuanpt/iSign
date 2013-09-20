package ooxml;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class KeyInfoKeySelector extends KeySelector
        implements KeySelectorResult {

    private X509Certificate certificate;
    private X509Certificate[] certChain;

    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
            throws KeySelectorException {
        ArrayList certList = new ArrayList();
        if (null == keyInfo) {
            throw new KeySelectorException("no ds:KeyInfo present");
        }
        List<XMLStructure> keyInfoContent = keyInfo.getContent();
        this.certificate = null;
        for (XMLStructure keyInfoStructure : keyInfoContent) {
            if (false == keyInfoStructure instanceof X509Data) {
                continue;
            }
            X509Data x509Data = (X509Data) keyInfoStructure;
            List x509DataList = x509Data.getContent();
            for (Iterator i$ = x509DataList.iterator(); i$.hasNext();) {
                Object x509DataObject = i$.next();
                if (false == x509DataObject instanceof X509Certificate) {
                    continue;
                }
                certList.add(x509DataObject);
            }
            if (!certList.isEmpty()) {
                this.certChain = ((X509Certificate[]) (X509Certificate[]) certList.toArray(new X509Certificate[0]));
                this.certificate = this.certChain[0];
                return this;
            }
        }
        throw new KeySelectorException("No key found!");
    }

    public Key getKey() {
        return this.certificate.getPublicKey();
    }

    public X509Certificate getCertificate() {
        return this.certificate;
    }

    public X509Certificate[] getCertChain() {
        return this.certChain;
    }
}