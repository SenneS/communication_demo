package be.senne

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.LocalTime
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun askYesNoQuestion(msg : String) : Boolean {
    while(true) {
        print("${msg} [y/n]: ")
        val response = readLine()
        when(response) {
            "Y", "y", "yes", "Yes", "YES", "Ja" -> {
                return true
            }
            "N", "n", "no", "No", "NO", "Nee" -> {
                return false
            }
        }
    }
}

//note: hoe stop ik iemand die de public keys van server/client kan onderscheppen en vervangen met een andere sleutel?
//signing werkt niet als ze de sleutels uit mijn applicatie kunnen halen.. acceptabel risico <-> public key met qr code doorgeven?
fun main(args: Array<String>) {
    println("### Communication Demo ###")

    //register bouncy castle provider
    Security.addProvider(BouncyCastleProvider())

    val hosting = askYesNoQuestion("Do you want to Host a sessions?")

    var clientSocket : Socket
    val dataInputStream : DataInputStream
    val dataOutputStream : DataOutputStream

    val ecParameter = ECGenParameterSpec("P-521")
    val keygen = KeyPairGenerator.getInstance("ECDH", "BC");
    keygen.initialize(ecParameter, SecureRandom())
    val key = keygen.genKeyPair()

    println(key.public.encoded.size)

    val theirKey = ByteArray(158)


    if(hosting) {
        val serverSocket = ServerSocket(21576)
        while(true) {
            println("Awaiting Client...")
            clientSocket = serverSocket.accept()
            val shouldAccept = askYesNoQuestion("Receiving Connection Request from ${clientSocket.inetAddress.hostAddress}, accept the request?");
            if(!shouldAccept) {
                clientSocket.close()
                continue
            }
            dataInputStream = DataInputStream(clientSocket.getInputStream())
            dataOutputStream = DataOutputStream(clientSocket.getOutputStream())

            //Send My Public Key
            dataOutputStream.write(key.public.encoded)
            //Receive Their Public Key
            dataInputStream.read(theirKey, 0, 158)
            break
        }
    }
    else {
        clientSocket = Socket("localhost", 21576)
        dataInputStream = DataInputStream(clientSocket.getInputStream())
        dataOutputStream = DataOutputStream(clientSocket.getOutputStream())

        //Receive Their Public Key
        dataInputStream.read(theirKey, 0, 158)
        //Send My Public Key
        dataOutputStream.write(key.public.encoded)
    }

    val keyFactory = KeyFactory.getInstance("ECDH", "BC")
    val theirPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(theirKey))

    val keyAgreement = KeyAgreement.getInstance("ECDH", "BC")
    keyAgreement.init(key.private)
    keyAgreement.doPhase(theirPublicKey, true)

    val sharedSecret = keyAgreement.generateSecret()
    val aesKey = sharedSecret.copyOfRange(0, 16)
    val aesIv = sharedSecret.copyOfRange(16, 32)

    println("Shared Secret: ${bytes2hex(sharedSecret)}")
    println("Aes Key: ${bytes2hex(aesKey)}")
    println("Aes Iv: ${bytes2hex(aesIv)}")


    GlobalScope.launch {
        while(true) {
            var msg : ByteArray
            withContext(Dispatchers.IO) {
                val msgLength = dataInputStream.readInt()
                msg = ByteArray(msgLength)
                dataInputStream.read(msg, 0, msgLength)
            }
            val decryptedMsg = cbcDecrypt(msg, aesKey, aesIv)
            writeToConsole("Them: ${decryptedMsg.decodeToString()}")
        }
    }

    while (true) {
        val msg = readLine() ?: continue
        val msgBytes = msg.encodeToByteArray()
        val encryptedMsg = cbcEncrypt(msgBytes, aesKey, aesIv)
        val length = encryptedMsg.size

        writeToConsole("Me: ${msg}")
        dataOutputStream.writeInt(length)
        dataOutputStream.write(encryptedMsg)
    }

}

private fun createKey(key: ByteArray) : SecretKey {
    return SecretKeySpec(key, "AES")
}
private fun createIv(iv: ByteArray) : IvParameterSpec {
    return IvParameterSpec(iv)
}
fun cbcEncrypt(input: ByteArray, key: ByteArray, iv: ByteArray) : ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/ZeroBytePadding", "BC");
    cipher.init(Cipher.ENCRYPT_MODE, createKey(key), createIv(iv))
    return cipher.doFinal(input)
}

fun cbcDecrypt(input: ByteArray, key: ByteArray, iv: ByteArray) : ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/ZeroBytePadding", "BC");
    cipher.init(Cipher.DECRYPT_MODE, createKey(key), createIv(iv))
    return cipher.doFinal(input)
}

@Synchronized
private fun writeToConsole(msg : String) {
    println("${LocalTime.now()}: ${msg}")
}

private fun bytes2hex(bytes : ByteArray) : String {
    return bytes.joinToString { byte -> byte.toUByte().toString(16) }
}