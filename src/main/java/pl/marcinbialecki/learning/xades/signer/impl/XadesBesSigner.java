package pl.marcinbialecki.learning.xades.signer.impl;

import com.google.common.collect.Collections2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import pl.marcinbialecki.learning.xades.KeyStoreLoader;
import pl.marcinbialecki.learning.xades.enums.Namespace;
import pl.marcinbialecki.learning.xades.exception.XadesSignerException;
import pl.marcinbialecki.learning.xades.model.Attachement;
import pl.marcinbialecki.learning.xades.model.CertificateMetadata;
import pl.marcinbialecki.learning.xades.signer.IProvider;
import pl.marcinbialecki.learning.xades.signer.ISigner;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Xades signer.
 */
public class XadesBesSigner implements ISigner {

    /**
     * LOGGER.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XadesBesSigner.class);

    /**
     * Qname for XMLNS.
     */
    private static final String XMLNS_QN = "xmlns";

    /**
     * ID Provider.
     */
    private IProvider<String> iProvider;

    /**
     * Document XML to sign content as byte array.
     */
    private byte[] documentToSign;

    /**
     * Attachements to sign with document.
     */
    private List<Attachement> attachementList;

    /**
     * Certificate metadata.
     */
    private CertificateMetadata certificateMetadata;

    /**
     * Is save to file signed document.
     */
    private boolean isSaveToFile;

    /**
     * Saved signed document file name;
     */
    private String saveToFileName;

    /**
     * Constructor.
     */
    public XadesBesSigner() {
        iProvider = new IdProvider();
    }

    public void setSaveToFile(boolean saveToFile) {
        isSaveToFile = saveToFile;
    }

    public void setSaveToFileName(String saveToFileName) {
        this.saveToFileName = saveToFileName;
    }

    @Override
    public void setDocumentToSign(byte[] documentToSign) {
        this.documentToSign = documentToSign;
    }

    @Override
    public void addAttachmentToSign(final Attachement attachement) {
        if (attachementList == null) {
            this.attachementList = new ArrayList<>();
        }
        // Add only if attachement is not null
        if (attachement != null) {
            this.attachementList.add(attachement);
        }
    }

    @Override
    public void setCertificateMetadata(CertificateMetadata certificateMetadata) {
        this.certificateMetadata = certificateMetadata;
    }

    @Override
    public byte[] signDocument() throws XadesSignerException {
        // Loading keystore
        KeyStoreLoader keyStoreLoader = new KeyStoreLoader();
        KeyStore ks = keyStoreLoader.loadKeyStore(this.certificateMetadata);

        // Get instance of XMLSignatureFactory
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        String signedPropertiesId = iProvider.provide();
        String signatureId = iProvider.provide();

        // References List
        List<Reference> refs = prepareReferences(fac, signedPropertiesId, this.attachementList);

        KeyStore.PrivateKeyEntry keyEntry = null;
        try {
            keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(this.certificateMetadata.getCertAlias(),
                    new KeyStore.PasswordProtection(this.certificateMetadata.getCertPassword().toCharArray()));
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("Erorr during get private key.", e);
            throw new XadesSignerException(e);
        } catch (final UnrecoverableEntryException e) {
            LOGGER.error("Erorr during get private key.", e);
            throw new XadesSignerException(e);
        } catch (final KeyStoreException e) {
            LOGGER.error("Erorr during get private key.", e);
            throw new XadesSignerException(e);
        }

        // Prepare KeyInfo data.
        KeyInfo ki = prepareKeyInfo(fac, keyEntry);

        InputStream is = new ByteArrayInputStream(this.documentToSign);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = null;
        try {
            doc = dbf.newDocumentBuilder().parse(is);
            is.close();
        } catch (final SAXException e) {
            LOGGER.error("Erorr during parsing document to sign.", e);
            throw new XadesSignerException(e);
        } catch (final IOException e) {
            LOGGER.error("Erorr during parsing document to sign.", e);
            throw new XadesSignerException(e);
        } catch (final ParserConfigurationException e) {
            LOGGER.error("Erorr during parsing document to sign.", e);
            throw new XadesSignerException(e);
        }

        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "ds");

        Element qualifyingProperties;
        try {
            qualifyingProperties = prepareSignatureElements(doc, signatureId, signedPropertiesId,
                    (X509Certificate) keyEntry.getCertificate());
        } catch (final Exception e) {
            LOGGER.error("Erorr during prepare qualifying properties element.", e);
            throw new XadesSignerException(e);
        }

        // Sign document
        DOMStructure qualifPropStruct = new DOMStructure(qualifyingProperties);
        List<DOMStructure> xmlObj = new ArrayList<DOMStructure>();
        xmlObj.add(qualifPropStruct);
        XMLObject object = fac.newXMLObject(xmlObj, null, null, null);

        List<XMLObject> objects = Collections.singletonList(object);

        try {
            SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                    (C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), refs);
            XMLSignature signature = fac.newXMLSignature(si, ki, objects, signatureId, null);
            signature.sign(dsc);
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("Erorr during signing document to sign.", e);
            throw new XadesSignerException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            LOGGER.error("Erorr during signing document to sign.", e);
            throw new XadesSignerException(e);
        } catch (final MarshalException e) {
            LOGGER.error("Erorr during signing document to sign.", e);
            throw new XadesSignerException(e);
        } catch (final XMLSignatureException e) {
            LOGGER.error("Erorr during signing document to sign.", e);
            throw new XadesSignerException(e);
        }

        if (isSaveToFile) {
            try {
                OutputStream os = new FileOutputStream(saveToFileName);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));
                os.close();
            } catch (final Exception e) {
                LOGGER.debug("Error saving file");
            }
        }

        byte[] signedDocument = null;
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            ByteArrayOutputStream outputByteStream = new ByteArrayOutputStream();
            trans.transform(new DOMSource(doc), new StreamResult(outputByteStream));
            signedDocument = outputByteStream.toByteArray();
        } catch (final Exception e) {
            LOGGER.debug("Error transform signed document to byte array");
        }
        return signedDocument;
    }

    /**
     * Prepare references od signed document.
     *
     * @param fac                XMLSignatureFactory.
     * @param signedPropertiesId Signed properties element id.
     * @param attachments        Attachments list.
     * @return List of Reference objects.
     */
    private List<Reference> prepareReferences(final XMLSignatureFactory fac,
                                              final String signedPropertiesId, final List<Attachement> attachments) throws XadesSignerException {
        List<Reference> refs = new ArrayList<Reference>();

        try {
            // Reference to signature of all document (required in XML Signature)
            Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                    null, iProvider.provide());
            refs.add(ref);

            // Signed properties reference (required in XADES)
            Reference signedPropertiesReference
                    = fac.newReference("#" + signedPropertiesId, fac.newDigestMethod(DigestMethod.SHA1, null), null,
                    "http://uri.etsi.org/01903#SignedProperties", iProvider.provide());
            refs.add(signedPropertiesReference);

            // if any attachment exist than add to reference list
            if (attachments != null && attachments.size() > 0) {
                for (Attachement attachement : attachments) {
                    MessageDigest sha1 = MessageDigest.getInstance("SHA1");

                    Reference attachmentRef = fac.newReference(attachement.getName(),
                            fac.newDigestMethod(DigestMethod.SHA1, null), null,
                            null, iProvider.provide(), sha1.digest(attachement.getContent()));

                    refs.add(attachmentRef);
                }
            }

        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("Erorr during prepare references process.", e);
            throw new XadesSignerException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            LOGGER.error("Erorr during prepare references process.", e);
            throw new XadesSignerException(e);
        }

        return refs;
    }

    /**
     * Prepare KeiInfo data.
     *
     * @param fac      XMLSignatureFactory.
     * @param keyEntry KeyStore.PrivateKeyEntry.
     * @return KeyInfo object.
     */
    private KeyInfo prepareKeyInfo(final XMLSignatureFactory fac, final KeyStore.PrivateKeyEntry keyEntry) {
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        return kif.newKeyInfo(Collections.singletonList(xd));
    }

    /**
     * Prepare signature elements,
     *
     * @param doc                Document.
     * @param signatureId        Id of signature element.
     * @param signedPropertiesId ID o signed properties element.
     * @param certificate        Certificate.
     * @return Prepared signature elements.
     * @throws Exception Exception.
     */
    private Element prepareSignatureElements(final Document doc, final String signatureId,
                                             final String signedPropertiesId, final X509Certificate certificate) throws Exception {
        // QualifyingProperties
        Element qualifyingProperties = createElement(doc, "QualifyingProperties", null, Namespace.XADES_NS.value());
        qualifyingProperties.setAttributeNS(null, "Target", "#" + signatureId);

        // SignedProperties
        Element signedProperties = createElement(doc, "SignedProperties", null, Namespace.XADES_NS.value());
        signedProperties.setAttributeNS(null, "Id", signedPropertiesId);
        Attr idAttr = signedProperties.getAttributeNode("Id");
        signedProperties.setIdAttributeNode(idAttr, true);
        signedProperties.setAttributeNS(Namespace.XMLNS_NS.value(), XMLNS_QN, Namespace.XADES_NS.value());

        // SignedSignatureProperties
        Element signedSignatureProperties = createElement(doc, "SignedSignatureProperties", null, Namespace.XADES_NS.value());

        // SigningTime
        Element signingTime = createElement(doc, "SigningTime", null, Namespace.XADES_NS.value());
        signingTime.setTextContent(dateConvert(new Date()).toXMLFormat());

        // SigningCertificate
        Element signingCertificate = createElement(doc, "SigningCertificate", null, Namespace.XADES_NS.value());

        // Cert
        Element cert = createElement(doc, "Cert", null, Namespace.XADES_NS.value());

        // CertDigest
        Element certDigest = createElement(doc, "CertDigest", null, Namespace.XADES_NS.value());

        // CertDigest DigestMethod
        Element digestMethod = createElement(doc, "DigestMethod", null, Namespace.XMLDIG_NS.value());
        digestMethod.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
        digestMethod.setAttributeNS(Namespace.XMLNS_NS.value(), XMLNS_QN, Namespace.XMLDIG_NS.value());

        // CertDigest DigestValue
        Element digestValue = createElement(doc, "DigestValue", null, Namespace.XMLDIG_NS.value());
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        BASE64Encoder base64Encoder = new BASE64Encoder();
        digestValue.setTextContent(base64Encoder.encode(sha1.digest(certificate.getEncoded())));
        digestValue.setAttributeNS(Namespace.XMLNS_NS.value(), XMLNS_QN, Namespace.XMLDIG_NS.value());
        // Add DigestMethod to CertDigest
        certDigest.appendChild(digestMethod);
        // Add DigestValue to CertDigest
        certDigest.appendChild(digestValue);

        // Add DigestMethod to Cert
        cert.appendChild(certDigest);

        // IssuerSerial
        Element issuerSerial = createElement(doc, "IssuerSerial", null, Namespace.XADES_NS.value());

        // IssuerName
        Element elX509IssuerName = createElement(doc, "X509IssuerName", null, Namespace.XMLDIG_NS.value());
        elX509IssuerName.setTextContent(certificate.getIssuerX500Principal().getName());
        elX509IssuerName.setAttributeNS(Namespace.XMLNS_NS.value(), XMLNS_QN, Namespace.XMLDIG_NS.value());
        // IssuerSerialNumber
        Element elX509SerialNumber = createElement(doc, "X509SerialNumber", null, Namespace.XMLDIG_NS.value());
        elX509SerialNumber.setTextContent(certificate.getSerialNumber().toString());
        elX509SerialNumber.setAttributeNS(Namespace.XMLNS_NS.value(), XMLNS_QN, Namespace.XMLDIG_NS.value());

        // Add elX509IssuerName to IssuerSerial
        issuerSerial.appendChild(elX509IssuerName);
        // Add elX509SerialNumber to IssuerSerial
        issuerSerial.appendChild(elX509SerialNumber);

        // Add IssuerSerial to Cert
        cert.appendChild(issuerSerial);

        // Add Cert to SigningCertificate
        signingCertificate.appendChild(cert);
        // Add SigningTime to SignedSignatureProperties
        signedSignatureProperties.appendChild(signingTime);
        // Add SigningCertificate to SignedSignatureProperties
        signedSignatureProperties.appendChild(signingCertificate);

        // Add SignedSignatureProperties to SignedProperties
        signedProperties.appendChild(signedSignatureProperties);

        Element signedDataObjectProperties = createElement(doc, "SignedDataObjectProperties", null, Namespace.XADES_NS.value());
        // Add SignedDataObjectProperties to SignedProperties
        signedProperties.appendChild(signedDataObjectProperties);
        signedDataObjectProperties.setAttributeNS(Namespace.XMLNS_NS.value(), XMLNS_QN, Namespace.XADES_NS.value());

        // Add SignedProperties to QualifyingProperties
        qualifyingProperties.appendChild(signedProperties);

        return qualifyingProperties;
    }

    /**
     * Create XML element.
     *
     * @param doc    Document.
     * @param tag    Tag name.
     * @param prefix Tag prefix.
     * @param nsURI  Tag namespace uri.
     * @return Created xml element tag.
     */
    private Element createElement(final Document doc, final String tag, final String prefix,
                                  final String nsURI) {
        String qName = prefix == null ? tag : prefix + ":" + tag;
        return doc.createElementNS(nsURI, qName);
    }

    /**
     * Date to xml format conversion.
     *
     * @param date Date to convert.
     * @return Converted date.
     */
    private XMLGregorianCalendar dateConvert(final Date date) {
        if (date == null) {
            return null;
        }
        GregorianCalendar gCalendar = new GregorianCalendar();
        gCalendar.setTime(date);
        XMLGregorianCalendar xmlCalendar = null;
        try {
            xmlCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(gCalendar);
        } catch (final DatatypeConfigurationException ex) {
            LOGGER.error("Convert date error.", ex);
        }
        return xmlCalendar;
    }

}