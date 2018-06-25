package com.acquitygroup.encryption;

// import junit.Test;
// import static org.junit.Assert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.spec.ECGenParameterSpec;



public class ECDHKeyAgreementTest {


    @Test
    public void ECDHKeyAgreement_Test_1() throws Exception {
        String message = "hello world";

        ECDHKeyAgreement ecdhkeyagreement = new ECDHKeyAgreement();

        ecdhkeyagreement.ECDHAgreement();


    }

    @Test
    public void ECDHKeyAgreement_Test_2() throws Exception {
        String message = "hello world";

        ECDHKeyAgreement ecdhkeyagreement = new ECDHKeyAgreement();

        ecdhkeyagreement.ECDHAgreement2();


    }
}