package pl.marcinbialecki.learning.xades.model;

import com.google.common.base.MoreObjects;

/**
 * Certificate metadata/
 */
public class CertificateMetadata {

    /**
     * Certificate location.
     */
    private String certificateLocation;

    /**
     * Keysttore password.
     */
    private String keystorePassword;

    /**
     * Certificate name.
     */
    private String certAlias;

    /**
     * Certificate password.
     */
    private String certPassword;

    /**
     * Default constructor marked as private.
     */
    private CertificateMetadata() {
    }

    /**
     * Constructor.
     * @param builder Builder instance.
     */
    private CertificateMetadata(final Builder builder) {
        this.certAlias = builder.certAlias;
        this.certificateLocation = builder.certificateLocation;
        this.certPassword = builder.certPassword;
        this.keystorePassword = builder.keystorePassword;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).toString();
    }

    public String getCertificateLocation() {
        return certificateLocation;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getCertAlias() {
        return certAlias;
    }

    public String getCertPassword() {
        return certPassword;
    }

    public static class Builder {
        private String certificateLocation;
        private String keystorePassword;
        private String certAlias;
        private String certPassword;

        public Builder setCertificateLocation(String certificateLocation) {
            this.certificateLocation = certificateLocation;
            return this;
        }

        public Builder setKeystorePassword(String keystorePassword) {
            this.keystorePassword = keystorePassword;
            return this;
        }

        public Builder setCertAlias(String certAlias) {
            this.certAlias = certAlias;
            return this;
        }

        public Builder setCertPassword(String certPassword) {
            this.certPassword = certPassword;
            return this;
        }

        public CertificateMetadata build() {
            return new CertificateMetadata(this);
        }
    }

}