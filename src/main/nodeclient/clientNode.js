
import 'ecdhNode.js'
import 'ecdsaNode.js'

var function clientApp () {


var AliceKey = ECDH();

// ECDSA();

// want to Post Alice's public key for ECDH exchange with REST server and get Bob's public key as response
fetch(AliceKey, URL);


}