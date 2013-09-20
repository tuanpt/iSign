package ooxml;

public class InsecureClientEnvironmentException extends Exception {

    private static final long serialVersionUID = 1L;
    private final boolean warnOnly;

    public InsecureClientEnvironmentException() {
        this(false);
    }

    public InsecureClientEnvironmentException(boolean warnOnly) {
        this.warnOnly = warnOnly;
    }

    public boolean isWarnOnly() {
        return this.warnOnly;
    }
}