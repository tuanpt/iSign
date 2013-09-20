package ooxml;

import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.input.ProxyInputStream;

public class NoCloseInputStream extends ProxyInputStream {

    public NoCloseInputStream(InputStream proxy) {
        super(proxy);
    }

    @Override
    public void close()
            throws IOException {
    }
}