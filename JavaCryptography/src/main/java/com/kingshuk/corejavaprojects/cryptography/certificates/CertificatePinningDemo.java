package com.kingshuk.corejavaprojects.cryptography.certificates;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;

public class CertificatePinningDemo {
    private static final Logger logger = LoggerFactory.getLogger(CertificatePinningDemo.class);

    public static void main(String[] args) throws Exception {
        final String hostname = "https://www.packtpub.com";

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");

        KeyManager [] keyManagers = {};

        final TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        final InputStream keyStore = new FileInputStream("src/main/resources/keystore");

        trustStore.load(keyStore, "changeit".toCharArray());

        trustManagerFactory.init(trustStore);

        sslContext.init(keyManagers, trustManagerFactory.getTrustManagers(), new SecureRandom());

        final URL url = new URL(hostname);

        final HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();

        urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
        urlConnection.addRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_2) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36");

        connectAndValidate(urlConnection);

    }

    private static void connectAndValidate(HttpsURLConnection urlConnection){
        try{
            urlConnection.connect();
            logger.info("Connected...");
            readBytes(urlConnection);
        }catch (SSLHandshakeException e) {
           logger.error("Certificate pin missing", e);
        } catch (SSLException e) {
            logger.error("Unable to access valid keystore", e);
        } catch (IOException e) {
            logger.error("Something went wrong", e);
        }
    }

    private static void readBytes(HttpsURLConnection urlConnection) {
        try (InputStream in = urlConnection.getInputStream()) {
            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            final byte[] bytes = new byte[1024];

            //I don't want to read the full html but this will do it.
            final int length = in.read(bytes);
            bout.write(bytes, 0, length);
           logger.info(bout.toString());
        } catch (IOException e) {
            logger.error("Something went wrong", e);
        }
    }
}
