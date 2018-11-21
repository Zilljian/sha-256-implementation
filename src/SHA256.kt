class SHA256(private val message: String) {
    @kotlin.ExperimentalUnsignedTypes private val K: Array<UInt> = arrayOf(
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u)

    @kotlin.ExperimentalUnsignedTypes private val H: Array<UInt> = arrayOf(
        0x6a09e667u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu,
        0x9b05688cu,
        0x1f83d9abu,
        0x5be0cd19u)
    @kotlin.ExperimentalUnsignedTypes private var W: Array<UInt> = Array(64){0u}

    private var messageDigest = ""


    init {
        computeHash()
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun computeHash() {
        for (m in padMessage()) {
            for (t in 0 until m.length / 32) {
                W[t] = (m.substring((t * 32) until ((t+1) * 32)).toUInt(2))
            }

            for (t in 16..63) {
                W[t] = (smallSigma1(W[t - 2]) +
                        W[t - 7] +
                        smallSigma0(W[t - 15]) +
                        W[t - 16])
            }

            var a: UInt = H[0]
            var b: UInt = H[1]
            var c: UInt = H[2]
            var d: UInt = H[3]
            var e: UInt = H[4]
            var f: UInt = H[5]
            var g: UInt = H[6]
            var h: UInt = H[7]


            for (t in 0..63) {
                val T1 = h + sigma1(e) + Ch(e, f, g) + K[t] + W[t]
                val T2 = sigma0(a) + Maj(a, b, c)
                h = g
                g = f
                f = e
                e = d + T1
                d = c
                c = b
                b = a
                a = T1 + T2
            }

            H[0] += a
            H[1] += b
            H[2] += c
            H[3] += d
            H[4] += e
            H[5] += f
            H[6] += g
            H[7] += h

        }

        buildMessage()
    }

    private fun padMessage(): ArrayList<String> {
        var binaryMessage = ""
        for (char in message) {
            binaryMessage += "0".repeat(8 - char.toInt().toString(2).length) +
                    char.toInt().toString(2)
        }
        val padBites = 512 - ((message.length * 8 + 1 + 64) % 512)
        val length = (8 * message.length).toString(2).length

        binaryMessage += '1' + "0".repeat(padBites + (64 - length)) +
                (8 * message.length).toString(2)

        val binaryList : ArrayList<String> = ArrayList(binaryMessage.length / 512)

        for (i in 0 until binaryMessage.length / 512) {
            binaryList.add(binaryMessage.substring((i * 512) until ((i+1) * 512)))
        }
        return binaryList
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun smallSigma0(word: UInt): UInt {
        return (((word shr 7) or (word shl 25)) xor
                ((word shr 18) or (word shl 14)) xor
                (word shr 3))
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun smallSigma1(word: UInt): UInt {
        return (((word shr 17) or (word shl 15)) xor
                ((word shr 19) or (word shl 13)) xor
                (word shr 10))
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun sigma0(word: UInt): UInt {
        return (((word shr 2) or (word shl 30)) xor
                ((word shr 13) or (word shl 19)) xor
                ((word shr 22) or (word shl 10)))
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun sigma1(word: UInt): UInt {
        return (((word shr 6) or (word shl 26)) xor
                ((word shr 11) or (word shl 21)) xor
                ((word shr 25) or (word shl 7)))
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun Maj(a: UInt, b: UInt, c: UInt): UInt {
        return ((a and b) xor (a and c) xor (b and c))
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun Ch(e: UInt, f: UInt, g: UInt): UInt {
        return ((e and f) xor ((e.inv()) and g))
    }

    fun hash()  = messageDigest

    @kotlin.ExperimentalUnsignedTypes
    private fun buildMessage() {
        for (item in H) {
            messageDigest += if (item.toString(16).length != 8)
                '0' + item.toString(16)
            else item.toString(16)
        }
    }
}