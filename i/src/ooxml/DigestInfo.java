package ooxml;

import java.io.Serializable;

public class DigestInfo
        implements Serializable {

    private static final long serialVersionUID = 1L;
    public final byte[] digestValue;
    public final String description;
    public final String digestAlgo;

    public DigestInfo(byte[] digestValue, String digestAlgo, String description) {
        this.digestValue = digestValue;
        this.digestAlgo = digestAlgo;
        this.description = description;
    }
}