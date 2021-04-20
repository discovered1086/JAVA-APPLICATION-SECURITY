package com.kingshuk.corejavaprojects.cryptography.certificates;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;

public class CertificateChainDemo {
    private static final Logger logger = LoggerFactory.getLogger(CertificateChainDemo.class);

    public static void main(String[] args) throws Exception {
        URL url = new URL("https://www.packtpub.com");

        final HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();

        urlConnection.connect();

        final Certificate[] serverCertificates = urlConnection.getServerCertificates();

        Arrays.stream(serverCertificates).forEach(CertificateChainDemo::printCert);

        logger.info("There are {} certificates", serverCertificates.length);
        Arrays.stream(serverCertificates).map(X509Certificate.class::cast)
                .forEach(x509 -> logger.info(x509.getIssuerDN().getName()));

        logger.info("The final certificate is for: {}", urlConnection.getPeerPrincipal());
    }

    private static void printCert(Certificate cert) {
        logger.info("Certificate is: {}", cert);
        if (cert instanceof X509Certificate) {
            try {
                ((X509Certificate) cert).checkValidity();
                logger.info("Certificate is active for current date");
            } catch (CertificateExpiredException e) {
                logger.info((Marker) Level.SEVERE, "Expired", e);
            } catch (CertificateNotYetValidException e) {
                logger.info((Marker) Level.SEVERE, "Not yet valid", e);
            }
        } else {
            logger.info("Odd, looks like there is a new type of certificate.");
        }
    }
}
