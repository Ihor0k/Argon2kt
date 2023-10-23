package ua.ihor0k.argon2

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class Argon2(
    private val hashLength: Int,
    private val parallelism: Int,
    private val memorySizeKB: Int,
    private val iterations: Int,
    private val type: Type,
    private val secret: ByteArray? = null,
    private val associatedData: ByteArray? = null,
    private val coroutineContext: CoroutineContext = Dispatchers.Default
) {
    private val blockCount = memorySizeKB - memorySizeKB % (SLICE_COUNT * parallelism)
    private val columnCount = blockCount / parallelism
    private val segmentLength = columnCount / SLICE_COUNT

    init {
        if (hashLength < 4) {
            throw IllegalArgumentException("Hash length must be at least 4")
        }
        if (memorySizeKB < 8 * parallelism) {
            throw IllegalArgumentException("Memory size myst be at least 8 * parallelism")
        }
        if (iterations < 1) {
            throw IllegalArgumentException("Number of iterations must be greater than 0")
        }
    }

    suspend fun hash(
        message: ByteArray,
        salt: ByteArray,
        secret: ByteArray? = this.secret,
        associatedData: ByteArray? = this.associatedData
    ): ByteArray {
        if (salt.size < 8) {
            throw IllegalArgumentException("Salt must be at least 8 bytes long")
        }
        val blocks = initBlocks(message, salt, secret, associatedData)
        val pseudoRandomGeneratorFactory = getPseudoRandomGeneratorFactory(blocks)
        val pseudoRandomGenerators = Array(parallelism) { lane ->
            pseudoRandomGeneratorFactory.getPseudoRandomGenerator(lane)
        }
        val bufferBlocks = Array(parallelism) { LongArray(BLOCK_SIZE_LONG) }
        withContext(coroutineContext) {
            for (pass in 0..<iterations) {
                val firstPass = pass == 0
                for (slice in 0..<SLICE_COUNT) {
                    val firstPassFirstSlice = firstPass && slice == 0
                    (0..<parallelism).map { lane ->
                        launch {
                            processSegment(
                                pass,
                                slice,
                                lane,
                                firstPass,
                                firstPassFirstSlice,
                                blocks,
                                pseudoRandomGenerators[lane],
                                bufferBlocks[lane]
                            )
                        }
                    }.joinAll()
                }
            }
        }

        val result = blocks[0][columnCount - 1]
        for (i in 1..<parallelism) {
            xor(result, blocks[i][columnCount - 1], result)
        }
        return blake2bHash(longArrayToByteArray(result), hashLength)
    }

    @OptIn(ExperimentalEncodingApi::class)
    suspend fun hashEncoded(
        message: ByteArray,
        salt: ByteArray,
        secret: ByteArray? = this.secret,
        associatedData: ByteArray? = this.associatedData
    ): String {
        val hash = hash(message, salt, secret, associatedData)
        val saltBase64Encoded = Base64.Default.encode(salt).trimEnd('=')
        val hashBase64Encoded = Base64.Default.encode(hash).trimEnd('=')
        return "\$${type.name}\$v=$VERSION\$m=$memorySizeKB,t=$iterations,p=$parallelism\$$saltBase64Encoded\$$hashBase64Encoded"
    }

    suspend fun verify(
        expectedHash: ByteArray,
        message: ByteArray,
        salt: ByteArray,
        secret: ByteArray? = this.secret,
        associatedData: ByteArray? = this.associatedData
    ): Boolean {
        val actualHash = hash(message, salt, secret, associatedData)
        return expectedHash.contentEquals(actualHash)
    }

    private fun initBlocks(
        message: ByteArray,
        salt: ByteArray,
        secret: ByteArray?,
        associatedData: ByteArray?
    ): Array<Array<LongArray>> {
        val secretSize = secret?.size ?: 0
        val associatedDataSize = associatedData?.size ?: 0
        val entropy = ByteArray(10 * Int.SIZE_BYTES + message.size + salt.size + secretSize + associatedDataSize)
        intToByteArray(parallelism, entropy, 0)
        intToByteArray(hashLength, entropy, 4)
        intToByteArray(memorySizeKB, entropy, 8)
        intToByteArray(iterations, entropy, 12)
        intToByteArray(VERSION, entropy, 16)
        intToByteArray(type.value, entropy, 20)
        intToByteArray(message.size, entropy, 24)
        message.copyInto(entropy, destinationOffset = 28)
        intToByteArray(salt.size, entropy, 28 + message.size)
        salt.copyInto(entropy, destinationOffset = 32 + message.size)
        if (secret != null) {
            intToByteArray(secret.size, entropy, 32 + message.size + salt.size)
            secret.copyInto(entropy, destinationOffset = 36 + message.size + salt.size)
        }
        if (associatedData != null) {
            intToByteArray(associatedData.size, entropy, 36 + message.size + salt.size + secretSize)
            associatedData.copyInto(entropy, destinationOffset = 40 + message.size + salt.size + secretSize)
        }

        val entropyHash = blake2b(entropy, BLAKE_DEFAULT_DIGEST_SIZE)
        val entropyHashWithZero = entropyHash + intToByteArray(0)
        val entropyHashWithOne = entropyHash + intToByteArray(1)
        val blocks = Array(parallelism) { Array(columnCount) { LongArray(BLOCK_SIZE_LONG) } }
        for (lane in 0..<parallelism) {
            val laneByteArray = intToByteArray(lane)
            blocks[lane][0] = byteArrayToLongArray(blake2bHash(entropyHashWithZero + laneByteArray, BLOCK_SIZE_BYTE))
            blocks[lane][1] = byteArrayToLongArray(blake2bHash(entropyHashWithOne + laneByteArray, BLOCK_SIZE_BYTE))
        }
        return blocks
    }

    private fun processSegment(
        pass: Int,
        slice: Int,
        lane: Int,
        firstPass: Boolean,
        firstPassFirstSlice: Boolean,
        blocks: Array<Array<LongArray>>,
        pseudoRandomGenerator: PseudoRandomGenerator,
        bufferBlock: LongArray
    ) {
        pseudoRandomGenerator.init(pass, slice, firstPass, firstPassFirstSlice)
        val startIndex = if (firstPassFirstSlice) 2 else 0
        for (index in startIndex..<segmentLength) {
            val currentColumn = slice * segmentLength + index
            val prevColumn = if (currentColumn == 0) columnCount - 1 else currentColumn - 1

            val pseudoRandom = pseudoRandomGenerator.getPseudoRandom(prevColumn, index)
            val refLane = if (firstPassFirstSlice) lane else getRefLane(pseudoRandom)
            val refColumn = getRefColumn(slice, index, firstPass, refLane == lane, pseudoRandom)

            val prevBlock = blocks[lane][prevColumn]
            val refBlock = blocks[refLane][refColumn]
            val currentBlock = blocks[lane][currentColumn]

            xor(prevBlock, refBlock, bufferBlock)
            if (firstPass) {
                xor(bufferBlock, applyBlakeRounds(bufferBlock), currentBlock)
            } else {
                xor(currentBlock, bufferBlock, applyBlakeRounds(bufferBlock), currentBlock)
            }
        }
    }

    private fun getPseudoRandomGeneratorFactory(blocks: Array<Array<LongArray>>): PseudoRandomGeneratorFactory {
        return when (type) {
            Argon2d -> Argon2dPseudoRandomGeneratorFactory(blocks)
            Argon2i -> Argon2iPseudoRandomGeneratorFactory()
            Argon2id -> Argon2idPseudoRandomGeneratorFactory(blocks)
        }
    }

    private fun getRefLane(pseudoRandom: Long): Int {
        return ((pseudoRandom ushr 32) % parallelism).toInt()
    }

    private fun getRefColumn(
        slice: Int,
        index: Int,
        firstPass: Boolean,
        sameLane: Boolean,
        pseudoRandom: Long
    ): Int {
        val startPos: Int
        val sliceOffset: Int
        if (firstPass) {
            startPos = 0
            sliceOffset = slice * segmentLength
        } else {
            startPos = (slice + 1) * segmentLength % columnCount
            sliceOffset = columnCount - segmentLength
        }
        val refAreaSize = when {
            sameLane -> sliceOffset + index - 1
            index == 0 -> sliceOffset - 1
            else -> sliceOffset
        }
        var pos = pseudoRandom and MASK_32L
        pos = (pos * pos) ushr 32
        pos = refAreaSize - 1 - (refAreaSize * pos ushr 32)
        return (startPos + pos.toInt()) % columnCount
    }

    private fun applyBlakeRounds(block: LongArray): LongArray {
        val out = block.copyOf()
        for (i in 0..<8) {
            val i16 = i * 16
            blakeRound(
                out,
                i16, i16 + 1, i16 + 2, i16 + 3,
                i16 + 4, i16 + 5, i16 + 6, i16 + 7,
                i16 + 8, i16 + 9, i16 + 10, i16 + 11,
                i16 + 12, i16 + 13, i16 + 14, i16 + 15
            )
        }

        for (i in 0..<8) {
            val i2 = i * 2
            blakeRound(
                out,
                i2, i2 + 1, i2 + 16, i2 + 17,
                i2 + 32, i2 + 33, i2 + 48, i2 + 49,
                i2 + 64, i2 + 65, i2 + 80, i2 + 81,
                i2 + 96, i2 + 97, i2 + 112, i2 + 113
            )
        }
        return out
    }

    private fun blakeRound(
        block: LongArray,
        v0: Int, v1: Int, v2: Int, v3: Int,
        v4: Int, v5: Int, v6: Int, v7: Int,
        v8: Int, v9: Int, v10: Int, v11: Int,
        v12: Int, v13: Int, v14: Int, v15: Int
    ) {
        f(block, v0, v4, v8, v12)
        f(block, v1, v5, v9, v13)
        f(block, v2, v6, v10, v14)
        f(block, v3, v7, v11, v15)
        f(block, v0, v5, v10, v15)
        f(block, v1, v6, v11, v12)
        f(block, v2, v7, v8, v13)
        f(block, v3, v4, v9, v14)
    }

    private fun f(block: LongArray, ai: Int, bi: Int, ci: Int, di: Int) {
        var a = block[ai]
        var b = block[bi]
        var c = block[ci]
        var d = block[di]
        a += b + 2 * (a and MASK_32L) * (b and MASK_32L)
        d = (d xor a).rotateRight(32)
        c += d + 2 * (c and MASK_32L) * (d and MASK_32L)
        b = (b xor c).rotateRight(24)
        a += b + 2 * (a and MASK_32L) * (b and MASK_32L)
        d = (d xor a).rotateRight(16)
        c += d + 2 * (c and MASK_32L) * (d and MASK_32L)
        b = (b xor c).rotateRight(63)
        block[ai] = a
        block[bi] = b
        block[ci] = c
        block[di] = d
    }

    private fun blake2bHash(data: ByteArray, size: Int): ByteArray {
        var outBuffer = intToByteArray(size) + data
        return if (size <= 64) {
            blake2b(outBuffer, size)
        } else {
            val out = ByteArray(size)
            val r = ((size + 31) / 32) - 2
            for (i in 1..r) {
                outBuffer = blake2b(outBuffer, BLAKE_DEFAULT_DIGEST_SIZE)
                outBuffer.copyInto(out, (i - 1) * 32, 0, 32)
            }
            val lastLength = size - 32 * r
            blake2b(outBuffer, lastLength).copyInto(out, destinationOffset = r * 32)
            out
        }
    }

    private fun xor(a: LongArray, b: LongArray, out: LongArray) {
        for (i in 0..<BLOCK_SIZE_LONG) {
            out[i] = a[i] xor b[i]
        }
    }

    private fun xor(a: LongArray, b: LongArray, c: LongArray, out: LongArray) {
        for (i in 0..<BLOCK_SIZE_LONG) {
            out[i] = a[i] xor b[i] xor c[i]
        }
    }

    private fun intToByteArray(x: Int): ByteArray {
        val bs = ByteArray(Int.SIZE_BYTES)
        intToByteArray(x, bs, 0)
        return bs
    }

    private fun intToByteArray(x: Int, bs: ByteArray, off: Int) {
        bs[off + 0] = x.toByte()
        bs[off + 1] = (x ushr 8).toByte()
        bs[off + 2] = (x ushr 16).toByte()
        bs[off + 3] = (x ushr 24).toByte()
    }

    private fun longArrayToByteArray(ls: LongArray): ByteArray {
        val lLen = ls.size
        val bs = ByteArray(lLen * Long.SIZE_BYTES)
        for (i in 0..<lLen) {
            val l = ls[i]
            val off = i * Long.SIZE_BYTES
            bs[off] = l.toByte()
            bs[off + 1] = (l ushr 8).toByte()
            bs[off + 2] = (l ushr 16).toByte()
            bs[off + 3] = (l ushr 24).toByte()
            bs[off + 4] = (l ushr 32).toByte()
            bs[off + 5] = (l ushr 40).toByte()
            bs[off + 6] = (l ushr 48).toByte()
            bs[off + 7] = (l ushr 56).toByte()
        }
        return bs
    }

    private fun byteArrayToLongArray(bs: ByteArray): LongArray {
        return byteArrayToLongArray(bs, 0, bs.size)
    }

    private fun byteArrayToLongArray(bs: ByteArray, bOff: Int, bLen: Int): LongArray {
        val lLen = bLen / Long.SIZE_BYTES
        val res = LongArray(lLen)
        for (i in 0..<lLen) {
            val off = bOff + i * Long.SIZE_BYTES
            res[i] = (bs[off].toLong() and 0xff) or
                    (bs[off + 1].toLong() and 0xff shl 8) or
                    (bs[off + 2].toLong() and 0xff shl 16) or
                    (bs[off + 3].toLong() and 0xff shl 24) or
                    (bs[off + 4].toLong() and 0xff shl 32) or
                    (bs[off + 5].toLong() and 0xff shl 40) or
                    (bs[off + 6].toLong() and 0xff shl 48) or
                    (bs[off + 7].toLong() and 0xff shl 56)
        }
        return res
    }

    private interface PseudoRandomGeneratorFactory {
        fun getPseudoRandomGenerator(lane: Int): PseudoRandomGenerator
    }

    private inner class Argon2dPseudoRandomGeneratorFactory(
        private val blocks: Array<Array<LongArray>>
    ) : PseudoRandomGeneratorFactory {
        override fun getPseudoRandomGenerator(lane: Int): PseudoRandomGenerator =
            DataDependentAddressingPseudoRandomGenerator(blocks[lane])
    }

    private inner class Argon2iPseudoRandomGeneratorFactory : PseudoRandomGeneratorFactory {
        override fun getPseudoRandomGenerator(lane: Int): PseudoRandomGenerator =
            DataIndependentAddressingPseudoRandomGenerator(lane)
    }

    private inner class Argon2idPseudoRandomGeneratorFactory(
        private val blocks: Array<Array<LongArray>>
    ) : PseudoRandomGeneratorFactory {
        override fun getPseudoRandomGenerator(lane: Int): PseudoRandomGenerator {
            return Argon2idPseudoRandomGenerator(blocks, lane)
        }
    }

    private inner class Argon2idPseudoRandomGenerator(
        private val blocks: Array<Array<LongArray>>,
        private val lane: Int
    ) : PseudoRandomGenerator {
        private var generator: PseudoRandomGenerator = DataIndependentAddressingPseudoRandomGenerator(lane)

        override fun init(pass: Int, slice: Int, firstPass: Boolean, firstPassFirstSlice: Boolean) {
            if (firstPass && slice == 2) {
                generator = DataDependentAddressingPseudoRandomGenerator(blocks[lane])
            }
            generator.init(pass, slice, firstPass, firstPassFirstSlice)
        }

        override fun getPseudoRandom(prevColumn: Int, index: Int): Long = generator.getPseudoRandom(prevColumn, index)
    }

    private interface PseudoRandomGenerator {
        fun init(pass: Int, slice: Int, firstPass: Boolean, firstPassFirstSlice: Boolean) {}
        fun getPseudoRandom(prevColumn: Int, index: Int): Long
    }

    private open inner class DataIndependentAddressingPseudoRandomGenerator(
        private val lane: Int
    ) : PseudoRandomGenerator {
        private val inputBlock = LongArray(BLOCK_SIZE_LONG)
        private val addressBlock = LongArray(BLOCK_SIZE_LONG)

        override fun init(pass: Int, slice: Int, firstPass: Boolean, firstPassFirstSlice: Boolean) {
            inputBlock[0] = pass.toLong()
            inputBlock[1] = lane.toLong()
            inputBlock[2] = slice.toLong()
            inputBlock[3] = blockCount.toLong()
            inputBlock[4] = iterations.toLong()
            inputBlock[5] = type.value.toLong()
            inputBlock[6] = 0

            if (firstPassFirstSlice) {
                nextAddresses()
            }
        }

        override fun getPseudoRandom(prevColumn: Int, index: Int): Long {
            val addressIndex = index % BLOCK_SIZE_LONG
            if (addressIndex == 0) {
                nextAddresses()
            }
            return addressBlock[addressIndex]
        }

        private fun nextAddresses() {
            inputBlock[6]++
            xor(inputBlock, applyBlakeRounds(inputBlock), addressBlock)
            xor(addressBlock, applyBlakeRounds(addressBlock), addressBlock)
        }
    }

    private open inner class DataDependentAddressingPseudoRandomGenerator(
        private val laneBlocks: Array<LongArray>
    ) : PseudoRandomGenerator {
        override fun getPseudoRandom(prevColumn: Int, index: Int): Long {
            return laneBlocks[prevColumn][0]
        }
    }

    private fun blake2b(data: ByteArray, digestLength: Int): ByteArray {
        val dataSize = data.size
        val chainValue = BLAKE_IV.copyOf()
        chainValue[0] = chainValue[0] xor (digestLength or 0x01010000).toLong()
        val nBlocks = (dataSize - 1) / BLAKE_BLOCK_SIZE_BYTES
        for (i in
        0..<nBlocks) {
            val block = byteArrayToLongArray(data, i * BLAKE_BLOCK_SIZE_BYTES, BLAKE_BLOCK_SIZE_BYTES)
            compress(chainValue, block, (i + 1) * BLAKE_BLOCK_SIZE_BYTES, 0)
        }
        val remainingData =
            data.copyInto(ByteArray(BLAKE_BLOCK_SIZE_BYTES), startIndex = BLAKE_BLOCK_SIZE_BYTES * nBlocks)
        val lastBlock = byteArrayToLongArray(remainingData, 0, BLAKE_BLOCK_SIZE_BYTES)
        compress(chainValue, lastBlock, dataSize, -1L)
        return longArrayToByteArray(chainValue).copyOfRange(0, digestLength)
    }

    private fun compress(
        chain: LongArray,
        block: LongArray,
        byteCounter: Int,
        finalizationFlag: Long
    ) {
        val state = chain + BLAKE_IV
        state[12] = state[12] xor byteCounter.toLong()
        state[14] = state[14] xor finalizationFlag

        for (r in 0..<BLAKE_ROUNDS) {
            val sigma = BLAKE_SIGMA[r]
            g(state, block[sigma[0]], block[sigma[1]], 0, 4, 8, 12)
            g(state, block[sigma[2]], block[sigma[3]], 1, 5, 9, 13)
            g(state, block[sigma[4]], block[sigma[5]], 2, 6, 10, 14)
            g(state, block[sigma[6]], block[sigma[7]], 3, 7, 11, 15)
            g(state, block[sigma[8]], block[sigma[9]], 0, 5, 10, 15)
            g(state, block[sigma[10]], block[sigma[11]], 1, 6, 11, 12)
            g(state, block[sigma[12]], block[sigma[13]], 2, 7, 8, 13)
            g(state, block[sigma[14]], block[sigma[15]], 3, 4, 9, 14)
        }

        for (i in chain.indices) {
            chain[i] = chain[i] xor state[i] xor state[i + 8]
        }
    }

    private fun g(state: LongArray, m1: Long, m2: Long, ai: Int, bi: Int, ci: Int, di: Int) {
        var a = state[ai]
        var b = state[bi]
        var c = state[ci]
        var d = state[di]
        a += b + m1
        d = (d xor a).rotateRight(32)
        c += d
        b = (b xor c).rotateRight(24)
        a += b + m2
        d = (d xor a).rotateRight(16)
        c += d
        b = (b xor c).rotateRight(63)
        state[ai] = a
        state[bi] = b
        state[ci] = c
        state[di] = d
    }

    sealed class Type(val value: Int, val name: String)
    data object Argon2d : Type(0, "argon2d")
    data object Argon2i : Type(1, "argon2i")
    data object Argon2id : Type(2, "argon2id")

    companion object {
        private val decodeRegex =
            "^\\\$(\\w+)\\\$v=(\\d+)\\\$m=(\\d+),t=(\\d+),p=(\\d+)\\\$([A-Za-z0-9+/]+)\\\$([A-Za-z0-9+/]+)\$".toRegex()

        private const val VERSION = 0x13
        private const val BLOCK_SIZE_BYTE = 1024
        private const val BLOCK_SIZE_LONG = BLOCK_SIZE_BYTE / Long.SIZE_BYTES
        private const val MASK_32L = 0xFFFFFFFFL
        private const val SLICE_COUNT = 4

        private const val BLAKE_DEFAULT_DIGEST_SIZE = 64
        private const val BLAKE_ROUNDS = 12
        private const val BLAKE_BLOCK_SIZE_BYTES = 128
        private val BLAKE_IV = longArrayOf(
            0x6a09e667f3bcc908,
            -0x4498517a7b3558c5,
            0x3c6ef372fe94f82b,
            -0x5ab00ac5a0e2c90f,
            0x510e527fade682d1,
            -0x64fa9773d4c193e1,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        )
        private val BLAKE_SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
        )

        @OptIn(ExperimentalEncodingApi::class)
        suspend fun verify(
            hashEncoded: String,
            message: ByteArray,
            secret: ByteArray? = null,
            associatedData: ByteArray? = null,
            coroutineContext: CoroutineContext = Dispatchers.Default
        ): Boolean {
            val matchResult = decodeRegex.find(hashEncoded) ?: throw IllegalArgumentException("Invalid encoding")
            val typeName = matchResult.groupValues[1]
            val versionStr = matchResult.groupValues[2]
            val memoryStr = matchResult.groupValues[3]
            val iterationsStr = matchResult.groupValues[4]
            val parallelismStr = matchResult.groupValues[5]
            val saltStr = matchResult.groupValues[6]
            val hashStr = matchResult.groupValues[7]

            val type = when (typeName) {
                Argon2d.name -> Argon2d
                Argon2i.name -> Argon2i
                Argon2id.name -> Argon2id
                else -> throw IllegalArgumentException("Invalid type")
            }
            if (versionStr.toInt() != VERSION) {
                throw IllegalArgumentException("Unsupported version")
            }
            val memory = memoryStr.toInt()
            val iterations = iterationsStr.toInt()
            val parallelism = parallelismStr.toInt()
            val salt = Base64.Default.decode(saltStr)
            val expectedHash = Base64.Default.decode(hashStr)
            return Argon2(expectedHash.size, parallelism, memory, iterations, type, coroutineContext = coroutineContext)
                .verify(expectedHash, message, salt, secret, associatedData)
        }

    }

}
