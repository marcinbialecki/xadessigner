package pl.marcinbialecki.learning.xades.enums;

/**
 * Created by Marcin Białecki on 2016-04-25.
 */
public enum Namespace {
    /**
     * XADES namespace URI.
     */
    XADES_NS ("http://uri.etsi.org/01903/v1.3.2#"),

    /**
     * XMLDIG namespace URI.
     */
    XMLDIG_NS ("http://www.w3.org/2000/09/xmldsig#"),

    /**
     * XMLNS namespace URI.
     */
    XMLNS_NS ("http://www.w3.org/2000/xmlns/");

    /**
     * Namespace uri.
     */
    private final String namespace;

    /**
     * Constructor.
     * @param namespace Namespace URI.
     */
    Namespace(final String namespace) {
        this.namespace = namespace;
    }

    public String value() {
        return namespace;
    }

}