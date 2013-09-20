package ooxml;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import org.w3c.dom.Document;

public abstract interface SignatureAspect {

    public abstract void preSign(XMLSignatureFactory paramXMLSignatureFactory, Document paramDocument, String paramString, List<Reference> paramList, List<XMLObject> paramList1)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException;
}