# Description
This is a utility to encrypt/decrypt using AES/CBC/PKCS5Padding algorithm
- Most common error_: "Invalid Key Size" error is most likely caused by not updating JCE strength policy, see above
- https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
**NOTE:** This example is built using **JDK8**, ultimate strength JCE (JDK8) and [Maven 3.x](http://maven.apache.org "Maven Documentation")

# Getting Started:
%git clone https://github.com/quantum-fusion/aes-256-encryption-utility

%mvn clean install 

# Installation
===================
## - Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8 Download
http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
## - JDK must have the unlimited strength policy for the JDK version

Extract the jar files from the zip and save them in ${java.home}/jre/lib/security/.

# To Run
====================

    mvn clean test

# To Use
====================

    # Key stored in JCEKS formatted Java keystore
    Key key = ....; // see tests pulling key from keystore
    // alternative is to hard-code key in string
    AESCipher cipher = new AESCipher(key);

    String encryptedMessage = cipher.getEncryptedMessage("this is message");
    String decryptedMessage = cipher.getDecryptedMessage(encryptedMessage);

    AESCipher cipherWithIv = new AESCipher(key, "0123456789012345".getBytes());
    String encryptedMessage = cipherWithIv.getEncryptedMessage("this is message");
    String decryptedMessage = cipherWithIv.getDecryptedMessage(encryptedMessage);

# Generate an AES-256 Key
======================

keytool -genseckey -alias jceksaes -keyalg AES -keysize 256 -storetype JCEKS -keypass mykeypass -storetype jceks -keystore aes-

keystore.jck -storepass mystorepass

# Android key generation example
https://developer.android.com/studio/publish/app-signing.html#signing-manually

keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-alias

# View AES-256 Key from command line
======================

mvn clean package // generate executable JAR file
java -Dkeystore=main-aes-keystore.jck -Dstorepass=mystorepass -Dalias=jceksaes -Dkeypass=mykeypass -jar target/example-encryption-util.jar <COMMAND like 'showKey'>

// or optionally with Maven (using the above defaults)
mvn exec:java

# Encrypt / Decrypt AES-256 from command line
======================

// Generate executable JAR with:  mvn package

// Ideally the IV passed in (0000000000000000) would be randomly generated
java -Dkeystore=main-aes-keystore.jck -Dstorepass=mystorepass -Dalias=jceksaes -Dkeypass=mykeypass -jar target/example-encryption-util.jar encrypt blahblahblah 0000000000000000

java -Dkeystore=main-aes-keystore.jck -Dstorepass=mystorepass -Dalias=jceksaes -Dkeypass=mykeypass -jar target/example-encryption-util.jar decrypt baN3CIAcVgq+AQr7lvKmLw== 0000000000000000

java -Dkeystore=main-aes-keystore.jck -Dstorepass=mystorepass -Dalias=jceksaes -Dkeypass=mykeypass -jar target/example-encryption-util.jar encrypt blahblahblah 0000000000000001

java -Dkeystore=main-aes-keystore.jck -Dstorepass=mystorepass -Dalias=jceksaes -Dkeypass=mykeypass -jar target/example-encryption-util.jar decrypt Wcaov8LNN4GJvp1bvOTJ0g== 0000000000000001

# Other references
===================
## Android integration frameworks (See https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf )
## AESCrypt Android (https://github.com/quantum-fusion/AESCrypt-Android)
## Whisper Systems Android encrypt (https://github.com/quantum-fusion/libsignal-service-java)

quantum-fusion Copyright 2018 - Use of this code and it's concepts are considered a Proof-of-concept and should not be used directly in any environment
