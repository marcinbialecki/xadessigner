package pl.marcinbialecki.learning.xades.exception;

/**
 * Exception from xades sign process.
 */
public class XadesSignerException extends Exception {

    /**
     * Constructor.
     */
    public XadesSignerException() {
        super();
    }

    /**
     * Constructor.
     *
     * @param e Exception.
     */
    public XadesSignerException(final Exception e) {
        super(e);
    }

    /**
     * Constructor.
     *
     * @param message Exception message.
     */
    public XadesSignerException(final String message) {
        super(message);
    }

}