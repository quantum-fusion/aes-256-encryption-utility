package com.acquitygroup.encryption;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.acquitygroup.encryption.*;

/**
 * Created by hottelet on 3/29/18.
 */
public class ClientMainApp {


    private static final Logger LOG = LoggerFactory.getLogger(ClientMainApp.class);

    private static void createClientSystemProperties() {
        System.setProperty("keystore","src/test/resources/client-aes-keystore.jck");
        System.setProperty("storepass","mystorepass");
        System.setProperty("alias","jceksaes");
        System.setProperty("keypass", "mykeypass");
    }

    public static void DiffieHellman() {

        try {

            // read client properties for Alice's public key
            createClientSystemProperties();

            String mode = "USE_SKIP_DH_PARAMS";

            DHKeyAgreement2 keyAgree = new DHKeyAgreement2();

            mode = "GENERATE_DH_PARAMS";

            keyAgree.setup(mode);

            //keyAgree.run();

            byte[] alicepublickeyEnc = keyAgree.AliceKeyGenerate();


            RestTemplate restTemplate = new RestTemplate();
            String hello = "hello";


            String s = restTemplate.getForObject("http://127.0.0.1:8080/restaurant/helloworld", String.class);

            System.out.println(s);

            PublicKeyEnc p = new PublicKeyEnc();
            p.setPublicKeyEnc(alicepublickeyEnc);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

// Jackson ObjectMapper to convert requestBody to JSON
            String json = new ObjectMapper().writeValueAsString(p);
            HttpEntity<String> entity = new HttpEntity<>(json, headers);

            System.out.println(json);

            // REST POST to Server
            ResponseEntity<String> response = restTemplate.postForEntity("http://127.0.0.1:8080/restaurant/postAlicePublicKey", entity, String.class);

            HttpStatus status = response.getStatusCode();
            String restCall = response.getBody();

            System.out.println("REST POST returned bob's hex public key:" + restCall);

            byte[] bobPublicKey = restTemplate.getForObject("http://127.0.0.1:8080/restaurant/getBobPublicKey", byte[].class);
            System.out.println("REST GET returned bob's hex public key: "  + DHKeyAgreement2.toHexString(bobPublicKey));

            // REST GET from Server
//            Quote quote = restTemplate.getForObject(
//                    "http://gturnquist-quoters.cfapps.io/api/random", Quote.class);
//            System.out.println(quote.toString());

            byte[] alicesecretkey = keyAgree.generateAliceSecretKey(bobPublicKey);

            System.out.println("alicekey length: " + alicesecretkey.length);

            String myMessage = "hello this is the test message";

            CryptoHelper c = new CryptoHelper();
            String encryptedMessage = c.encryptMessage(DHKeyAgreement2.toHex(alicesecretkey).substring(0,32),myMessage); //ToDo Is this a 256 bit key ?

            System.out.println("encrypted message: " + encryptedMessage + "\n");

            String myHMAC = HMAC.calculateHMAC(myMessage,DHKeyAgreement2.toHex(alicesecretkey).substring(0,32), "HmacSHA256"); //ToDo Is this a 256 bit key ?

            System.out.println("HMAC SHA256: " + myHMAC);

            String decryptedMessage = c.decryptMessage(DHKeyAgreement2.toHex(alicesecretkey).substring(0,32), encryptedMessage);

            System.out.println("decrypted message: " + decryptedMessage + "\n");

            String myHMACdecrypted = HMAC.calculateHMAC(decryptedMessage,DHKeyAgreement2.toHex(alicesecretkey).substring(0,32), "HmacSHA256"); //ToDo Is this a 256 bit key ?

            System.out.println("HMAC SHA256: " + myHMACdecrypted);

            //  keyAgree.compareSecrets(alicesecretkey, bobsecretkey);
            //  System.out.println("bobkey length: " + bobsecretkey.length);

        } catch (Exception e) {
            e.printStackTrace();
        }


    }



    public static void main(String[] args) {


      DiffieHellman();

    }
}
