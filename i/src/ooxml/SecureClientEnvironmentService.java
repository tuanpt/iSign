package ooxml;

import java.util.List;

public abstract interface SecureClientEnvironmentService {

    public abstract void checkSecureClientEnvironment(String paramString1, String paramString2, String paramString3, String paramString4, String paramString5, String paramString6, String paramString7, String paramString8, String paramString9, String paramString10, int paramInt, String paramString11, List<String> paramList)
            throws InsecureClientEnvironmentException;
}