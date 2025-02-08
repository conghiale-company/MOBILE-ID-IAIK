package vn.mobileid.testiaik.hsm;

public class HSMException extends Exception {

    private static final long serialVersionUID = -6122994861628966528L;
    protected static String diagnostic = "HSM Exception";

    public HSMException() {
        super(diagnostic);
    }

    public HSMException(final String detail) {
        super(diagnostic + ": " + detail);
    }
}
