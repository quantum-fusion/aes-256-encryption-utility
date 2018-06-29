package com.acquitygroup.encryption;

import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.gson.Gson;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

//import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
//import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
//import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.BigIntegers;
//import org.xipki.common.util.ParamUtil;

// import org.xmldap.crypto.KDFConcatGenerator; //ToDo missing library

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

import javax.crypto.KeyAgreement;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Enumeration;
import java.util.Map;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


public class ECDHKeyAgreement {

    void ECDHAgreement() {

        try {

            Security.addProvider(new BouncyCastleProvider());

            // Alice sets up the exchange
            KeyPairGenerator aliceKeyGen = KeyPairGenerator.getInstance("ECDH", "BC");
           // aliceKeyGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
            aliceKeyGen.initialize(new ECGenParameterSpec("secp521r1"), new SecureRandom());

            KeyPair alicePair = aliceKeyGen.generateKeyPair();
            ECPublicKey alicePub = (ECPublicKey) alicePair.getPublic();
            ECPrivateKey alicePvt = (ECPrivateKey) alicePair.getPrivate();

            byte[] alicePubEncoded = alicePub.getEncoded();
            byte[] alicePvtEncoded = alicePvt.getEncoded();

            System.out.println("Alice public: " + DatatypeConverter.printHexBinary(alicePubEncoded));
            System.out.println("Alice private: " + DatatypeConverter.printHexBinary(alicePvtEncoded));


// POST hex(alicePubEncoded)

// Bob receives Alice's public key

            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey remoteAlicePub = kf.generatePublic(new X509EncodedKeySpec(alicePubEncoded));

            KeyPairGenerator bobKeyGen = KeyPairGenerator.getInstance("ECDH", "BC");
      //      bobKeyGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
            bobKeyGen.initialize(new ECGenParameterSpec("secp521r1"), new SecureRandom());

            KeyPair bobPair = bobKeyGen.generateKeyPair();
            ECPublicKey bobPub = (ECPublicKey) bobPair.getPublic();
            ECPrivateKey bobPvt = (ECPrivateKey) bobPair.getPrivate();

            byte[] bobPubEncoded = bobPub.getEncoded();
            byte[] bobPvtEncoded = bobPvt.getEncoded();

            System.out.println("Bob public: " + DatatypeConverter.printHexBinary(bobPubEncoded));
            System.out.println("Bob private: " + DatatypeConverter.printHexBinary(bobPvtEncoded));



            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("ECDH");
            bobKeyAgree.init(bobPvt);
            bobKeyAgree.doPhase(alicePair.getPublic(), true);

            System.out.println("hello");

            System.out.println("Bob secret: " + DatatypeConverter.printHexBinary(bobKeyAgree.generateSecret()));


// RESPOND hex(bobPubEncoded)

// Alice derives secret

            KeyFactory aliceKf = KeyFactory.getInstance("EC");
            PublicKey remoteBobPub = aliceKf.generatePublic(new X509EncodedKeySpec(bobPubEncoded));

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH");
            aliceKeyAgree.init(alicePvt);
            aliceKeyAgree.doPhase(bobPair.getPublic(), true);

            System.out.println("Alice secret: " + DatatypeConverter.printHexBinary(aliceKeyAgree.generateSecret()));

        }
        catch (Exception e) {

            System.out.println("Exception: " + e);

        }

    }

    void ECDHAgreement2()
    {

    try {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger(
                "fffffffffffffffffffffffffffffffeffffffffffffffff", 16)), new BigInteger(
                "fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger(
                "fffffffffffffffffffffffffffffffefffffffffffffffc", 16));

        ECParameterSpec ecSpec = new ECParameterSpec(curve, new ECPoint(new BigInteger(
                "fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger(
                "fffffffffffffffffffffffffffffffefffffffffffffffc", 16)), new BigInteger(
                "fffffffffffffffffffffffffffffffefffffffffffffffc", 16), 1);

        keyGen.initialize(ecSpec, new SecureRandom());

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");

        System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
        System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));

    }
    catch (Exception e)
    {
     System.out.println("exception: " + e);

    }

}





}
