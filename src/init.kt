import java.io.File
import java.io.InputStream

fun main() {
    val inputStream: InputStream = File("input.txt").inputStream()
    val inputString = inputStream.bufferedReader().use { it.readText() }
    val hashM = SHA256(inputString)
    println(hashM.hash())
}