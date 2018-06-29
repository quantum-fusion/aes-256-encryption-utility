package com.acquitygroup.encryption;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public class ECCCipher {


    public byte[] sign(PrivateKey privateKey, String message) throws Exception {
        Signature signature = Signature.getInstance("SHA1withECDSA");
        signature.initSign(privateKey);

        signature.update(message.getBytes());

        return signature.sign();
    }


    public boolean verify(PublicKey publicKey, byte[] signed, String message) throws Exception {
        Signature signature = Signature.getInstance("SHA1withECDSA");
        signature.initVerify(publicKey);

        signature.update(message.getBytes());

        return signature.verify(signed);
    }


    public PrivateKey generatePrivateKey(byte[] keyBin) throws InvalidKeySpecException, NoSuchAlgorithmException {
        // ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
         ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp521r1");

        KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());

        // ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
         ECNamedCurveSpec params = new ECNamedCurveSpec("secp521r1", spec.getCurve(), spec.getG(), spec.getN());

        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(new BigInteger(keyBin), params);
        return kf.generatePrivate(privKeySpec);
    }


    public PublicKey generatePublicKey(byte[] keyBin) throws InvalidKeySpecException, NoSuchAlgorithmException {
       //ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
       ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp521r1");

        KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
      //  ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
          ECNamedCurveSpec params = new ECNamedCurveSpec("secp521r1", spec.getCurve(), spec.getG(), spec.getN());

        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), keyBin);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        return kf.generatePublic(pubKeySpec);
    }

}
