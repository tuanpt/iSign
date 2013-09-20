package ooxml;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;

public abstract interface TemporaryDataStorage {

    public abstract OutputStream getTempOutputStream();

    public abstract InputStream getTempInputStream();

    public abstract void setAttribute(String paramString, Serializable paramSerializable);

    public abstract Serializable getAttribute(String paramString);
}