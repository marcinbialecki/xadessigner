package pl.marcinbialecki.learning.xades.signer;

import pl.marcinbialecki.learning.xades.exception.XadesSignerException;
import pl.marcinbialecki.learning.xades.model.Attachement;
import pl.marcinbialecki.learning.xades.model.CertificateMetadata;

/**
 * Sing interface.
 */
public interface ISigner {

    /**
     * Set document XML to sign.
     * @param documentToSign Document content as byte array.
     */
    void setDocumentToSign(final byte[] documentToSign);

    /**
     * Add attachement to signed document.
     * @param attachement Attachment instance.
     */
    void addAttachmentToSign(final Attachement attachement);

    /**
     * Set certificate metadata (like location, password, alias)
     * @param certificateMetadata Certificate metadata.
     */
    void setCertificateMetadata(final CertificateMetadata certificateMetadata);

    /**
     * Sign document.
     *
     * @return Signed document content as byte array.
     * @throws XadesSignerException Exception.
     */
    byte[] signDocument() throws XadesSignerException;

}