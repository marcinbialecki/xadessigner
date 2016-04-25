import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.marcinbialecki.learning.xades.director.XadesDirector;
import pl.marcinbialecki.learning.xades.exception.XadesSignerException;
import pl.marcinbialecki.learning.xades.model.CertificateMetadata;
import pl.marcinbialecki.learning.xades.signer.impl.XadesBesSigner;

import java.io.File;
import java.io.FileInputStream;

/**
 * XADES Test.
 */
public class XadesTest {
    /**
     * LOGGER.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XadesTest.class);

    /**
     * Document xml to sign name.
     */
    private static final String DOC_TO_SIGN_NAME = "C:\\purchaseOrder.xml";

    public void testXades() {
        // given
        XadesBesSigner xadesBesSigner = new XadesBesSigner();
        xadesBesSigner.setSaveToFile(true);
        xadesBesSigner.setSaveToFileName("C:\\signedDocumentPurchaseOrder.xml");
        xadesBesSigner.setCertificateMetadata(new CertificateMetadata.Builder()
                .setCertAlias("certificateAlias")
                .setCertificateLocation("path_to_cert")
                .setCertPassword("changeit")
                .setKeystorePassword("changeit").build());

        // XML document to sign
        try {
            File file = new File(DOC_TO_SIGN_NAME);
            FileInputStream is = new FileInputStream(file);
            byte fileContent[] = new byte[(int) file.length()];
            is.read(fileContent);
            xadesBesSigner.setDocumentToSign(fileContent);
        } catch (final java.io.IOException e) {
            LOGGER.error("Erorr reading document xml to sign", e);
        }

        XadesDirector xadesDirector = new XadesDirector(xadesBesSigner);

        // when
        byte[] signedDocument = null;
        try {
            signedDocument = xadesDirector.sign();
        } catch (final XadesSignerException e) {

        }

        LOGGER.debug(new String(signedDocument));
    }

}
