package pl.marcinbialecki.learning.xades;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.marcinbialecki.learning.xades.exception.XadesSignerException;
import pl.marcinbialecki.learning.xades.model.CertificateMetadata;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * Keystore loader.
 */
public class KeyStoreLoader {

    /**
     * LOGGER.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreLoader.class);

    /**
     * Keystore type.
     */
    private static final String KEYSTORE_TYPE = "pkcs12";

    /**
     * Load keystore.
     * @param certificateMetadata Certificate metadata.
     *
     * @return Keystore instance.
     */
    public KeyStore loadKeyStore(final CertificateMetadata certificateMetadata) throws XadesSignerException {
        if (certificateMetadata == null) {
            throw new XadesSignerException("certificateMetadata is null");
        }
        KeyStore certificate;
        try {
            certificate = KeyStore.getInstance(KEYSTORE_TYPE);

            InputStream is;
            if (certificateMetadata.getCertificateLocation().startsWith("classpath:")) {
                String certLocationLocal = certificateMetadata.getCertificateLocation().substring("classpath:".length()
                        , certificateMetadata.getCertificateLocation().length());
                is = this.getClass().getClassLoader().getResourceAsStream(certLocationLocal);
            }
            else {
                is = new FileInputStream(certificateMetadata.getCertificateLocation());
            }
            certificate.load(is, certificateMetadata.getKeystorePassword().toCharArray());
        }
        catch (final Exception e) {
            LOGGER.error("Error loading certificate.", e);
            throw new XadesSignerException("Erorr during load keystore");
        }

        return certificate;
    }

}