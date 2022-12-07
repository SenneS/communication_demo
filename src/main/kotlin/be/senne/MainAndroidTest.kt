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
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.KeyAgreement


var privateKey = "3081F7020100301006072A8648CE3D020106052B810400230481DF3081DC020101044200C8285467C01092FEBA4DA10D3AF1734930CDC1D60A71A9D4F4A054E055237C8D97B2932B43213B16920DF5F4D6181E6C6749198EB6C7ED40A4B4B653BF53BA50E9A00706052B81040023A181890381860004010692271266EC2CBB7BE2EDE94556C7538A8CFEE1A3182594CEF5410312524110ACE98E0E209D94BE8FCF04810FD3A9F39017C6735714D5224C93F85212003D9D12012B7CB0D25962489F6CF1BADE54665BB0B81E11EE72414D112FD5061AF71576908E3D0931D8E0170DBF956A2270D69A3DB3D26AD65B94881EBA99BDC7B8EB8C2E59"

fun main() {
    println("### Communication Demo 2 ###")

    //register bouncy castle provider
    Security.addProvider(BouncyCastleProvider())

    val hosting = askYesNoQuestion("Do you want to Host a sessions?")

    var clientSocket : Socket
    val dataInputStream : DataInputStream
    val dataOutputStream : DataOutputStream

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
            break
        }
    }
    else {
        clientSocket = Socket("192.168.83.46", 21576)
    }
    dataInputStream = DataInputStream(clientSocket.getInputStream())
    dataOutputStream = DataOutputStream(clientSocket.getOutputStream())


    print("Enter their public key base64: ")
    val msg0 = readLine()
    if(msg0 == null) { return }

    val theirPublicKeyBytes = Base64.getDecoder().decode(msg0)

    val keyFactory = KeyFactory.getInstance("ECDH", "BC")
    val myPrivate = keyFactory.generatePrivate(PKCS8EncodedKeySpec(hex2bytes(privateKey)))
    val theirPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(theirPublicKeyBytes))

    val keyAgreement = KeyAgreement.getInstance("ECDH", "BC")
    keyAgreement.init(myPrivate)
    keyAgreement.doPhase(theirPublicKey, true)

    val sharedSecret = keyAgreement.generateSecret()
    val aesKey = sharedSecret.copyOfRange(0, 16)
    val aesIv = sharedSecret.copyOfRange(16, 32)

    println("Shared Secret: ${bytes2hex(sharedSecret)}")
    println("Aes Key: ${bytes2hex(aesKey)}")
    println("Aes Iv: ${bytes2hex(aesIv)}")


    GlobalScope.launch {
        while(true) {
            withContext(Dispatchers.IO) {
                val msgLength = dataInputStream.readInt()
                println("received a message with length... $msgLength")
                val msg = ByteArray(msgLength)
                dataInputStream.read(msg, 0, msgLength)
                val decryptedMsg = cbcDecrypt(msg, aesKey, aesIv)
                writeToConsole("Them: ${decryptedMsg.decodeToString()}")
            }
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