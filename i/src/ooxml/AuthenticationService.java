package ooxml;

import java.security.cert.X509Certificate;
import java.util.List;

public abstract interface AuthenticationService {

    public abstract void validateCertificateChain(List<X509Certificate> paramList)
            throws SecurityException;
}