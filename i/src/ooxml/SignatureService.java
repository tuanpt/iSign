package ooxml;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

public abstract interface SignatureService {

    public abstract String getFilesDigestAlgorithm();

    public abstract DigestInfo preSign(List<DigestInfo> paramList, List<X509Certificate> paramList1)
            throws NoSuchAlgorithmException;

    public abstract void postSign(byte[] paramArrayOfByte, List<X509Certificate> paramList);
}