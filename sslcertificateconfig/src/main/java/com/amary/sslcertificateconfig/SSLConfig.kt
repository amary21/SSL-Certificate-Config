package com.amary.sslcertificateconfig

import android.content.Context
import android.net.http.SslCertificate
import java.io.IOException
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.cert.CertificateException

object SSLConfig {
    @Throws(
        CertificateException::class,
        IOException::class,
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        KeyManagementException::class
    )

    fun getSSLConfiguration(context: Context, sslCertificate: Int): SSLContext {
        // Creating an SSLSocketFactory that uses our TrustManager
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, getTrustManager(context, sslCertificate).trustManagers, null)
        return sslContext
    }

    fun getTrustManagerFactory(context: Context, sslCertificate: Int): X509TrustManager {
        val trustManagerFactory = getTrustManager(context, sslCertificate)
        val trustManagers = trustManagerFactory.trustManagers
        if (trustManagers.size != 1 || trustManagers[0] !is X509TrustManager) {
            throw IllegalStateException("Unexpected default trust managers:" + Arrays.toString(trustManagers))
        }
        return trustManagers[0] as X509TrustManager
    }

    private fun getKeystore(context: Context, sslCertificate: Int): KeyStore {
        // Creating a KeyStore containing our trusted CAs
        val keyStoreType = KeyStore.getDefaultType()
        val keyStore = KeyStore.getInstance(keyStoreType)
        keyStore.load(null, null)
        keyStore.setCertificateEntry("ca", getCertificate(context, sslCertificate))
        return keyStore
    }

    private fun getTrustManager(context: Context, sslCertificate: Int): TrustManagerFactory {
        // Creating a TrustManager that trusts the CAs in our KeyStore.
        val trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
        val trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm)
        trustManagerFactory.init(getKeystore(context, sslCertificate))
        return trustManagerFactory
    }

    private fun getCertificate(context: Context, sslCertificate: Int): Certificate? {
        // Loading CAs from file
        val certificateFactory: CertificateFactory? = CertificateFactory.getInstance("X.509")
        return context.resources?.openRawResource(sslCertificate)
            .use { cert -> certificateFactory?.generateCertificate(cert) }
    }
}