package ooxml;

import java.io.IOException;
import java.io.OutputStream;
import org.apache.commons.io.output.ProxyOutputStream;

public class NoCloseOutputStream extends ProxyOutputStream {

    public NoCloseOutputStream(OutputStream proxy) {
        super(proxy);
    }

    @Override
    public void close()
            throws IOException {
    }
}