package com.acquitygroup.encryption;

// import junit.Test;
// import static org.junit.Assert.*;

import com.sun.tools.javac.util.Assert;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.*;

// import io.jsondb.crypto.ICipher;
import org.junit.jupiter.api.Test;

public class ECCCipherTest {

    private final KeyPairGenerator keygen;

    public ECCCipherTest() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        this.keygen = KeyPairGenerator.getInstance("ECDSA", "BC");
        keygen.initialize(new ECGenParameterSpec("brainpoolP384r1"));
    }

    @Test
    public void ECC_CipherTest_1() throws Exception {
        String message = "hello world";

        ECCCipher cipher = new ECCCipher();
        KeyPair keyPair = keygen.generateKeyPair();

        byte[] encrypted = cipher.sign(keyPair.getPrivate(), message);

        System.out.println(encrypted);

        // AssertTrue(cipher.verify(keyPair.getPublic(), encrypted, message));
    }

    @Test
    public void ECC_CipherTest_2() throws Exception {
        String message = "hello world";

        ECCCipher cipher = new ECCCipher();
        KeyPair keyPair = keygen.generateKeyPair();

        byte[] encrypted = cipher.sign(keyPair.getPrivate(), message);

        // Expect True, using Public key from KeyPair from generateKeyPair()
        System.out.println(cipher.verify(keyPair.getPublic(), encrypted, message));
        // AssertTrue(cipher.verify(keyPair.getPublic(), encrypted, message)); //ToDo need to add Junit support

        // generated private key algorithmically
        byte[] encryptedmessage = cipher.sign(cipher.generatePrivateKey(encrypted), message);
        System.out.println(encryptedmessage); //ToDo bug why doesn't this encrypted message verify after signing?
    //    System.out.println(cipher.verify(cipher.getPubKeyFromCurve(keyPair.getPublic().getEncoded(),"secp256r1"), encryptedmessage, message)); //ToDo bug java.lang.RuntimeException: Invalid point encoding 0x30

    }


}