package ooxml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class OOXMLTestDataStorage
        implements TemporaryDataStorage {

    private ByteArrayOutputStream outputStream;
    private Map<String, Serializable> attributes;

    public OOXMLTestDataStorage() {
        this.outputStream = new ByteArrayOutputStream();
        this.attributes = new HashMap();
    }

    @Override
    public InputStream getTempInputStream() {
        byte[] data = this.outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        return inputStream;
    }

    @Override
    public OutputStream getTempOutputStream() {
        return this.outputStream;
    }

    @Override
    public Serializable getAttribute(String attributeName) {
        return (Serializable) this.attributes.get(attributeName);
    }

    @Override
    public void setAttribute(String attributeName, Serializable attributeValue) {
        this.attributes.put(attributeName, attributeValue);
    }
}