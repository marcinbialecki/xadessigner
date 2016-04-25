package pl.marcinbialecki.learning.xades.director;

import pl.marcinbialecki.learning.xades.exception.XadesSignerException;
import pl.marcinbialecki.learning.xades.signer.ISigner;

/**
 * Xades signer director.
 */
public class XadesDirector {

    /**
     * Xades signer.
     */
    private ISigner signer;

    /**
     * Constructor.
     *
     * @param signer Signer instance.
     */
    public XadesDirector(final ISigner signer) {
        this.signer = signer;
    }

    public byte[] sign() throws XadesSignerException {
        return signer.signDocument();
    }

}