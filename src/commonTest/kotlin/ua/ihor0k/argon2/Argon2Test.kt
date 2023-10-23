package ua.ihor0k.argon2

import kotlinx.coroutines.test.runTest
import kotlin.math.pow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

class Argon2Test {
    @Test
    fun positiveTest1() = runTest {
        hashTest(
            2, 16, 1, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=65536,t=2,p=1\$c29tZXNhbHQ\$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA"
        )
    }

    @Test
    fun positiveTest2() = runTest(timeout = 30.seconds) {
        hashTest(
            2, 20, 1, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=1048576,t=2,p=1\$c29tZXNhbHQ\$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E"
        )
    }

    @Test
    fun positiveTest3() = runTest {
        hashTest(
            2, 18, 1, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=262144,t=2,p=1\$c29tZXNhbHQ\$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s"
        )
    }

    @Test
    fun positiveTest4() = runTest {
        hashTest(
            2, 8, 1, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=256,t=2,p=1\$c29tZXNhbHQ\$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8"
        )
    }

    @Test
    fun positiveTest5() = runTest {
        hashTest(
            2, 8, 2, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=256,t=2,p=2\$c29tZXNhbHQ\$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E"
        )
    }

    @Test
    fun positiveTest6() = runTest {
        hashTest(
            1, 16, 1, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=65536,t=1,p=1\$c29tZXNhbHQ\$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8"
        )
    }

    @Test
    fun positiveTest7() = runTest {
        hashTest(
            4, 16, 1, "password", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=65536,t=4,p=1\$c29tZXNhbHQ\$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls"
        )
    }

    @Test
    fun positiveTest8() = runTest {
        hashTest(
            2, 16, 1, "differentpassword", "somesalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=65536,t=2,p=1\$c29tZXNhbHQ\$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4"
        )
    }

    @Test
    fun positiveTest9() = runTest {
        hashTest(
            2, 16, 1, "password", "diffsalt", Argon2.Argon2i,
            "\$argon2i\$v=19\$m=65536,t=2,p=1\$ZGlmZnNhbHQ\$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE"
        )
    }

    @Test
    fun positiveTest10() = runTest {
        hashTest(
            2, 16, 1, "password", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=65536,t=2,p=1\$c29tZXNhbHQ\$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
        )
    }

    @Test
    fun positiveTest11() = runTest {
        hashTest(
            2, 18, 1, "password", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=262144,t=2,p=1\$c29tZXNhbHQ\$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow"
        )
    }

    @Test
    fun positiveTest12() = runTest {
        hashTest(
            2, 8, 1, "password", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=256,t=2,p=1\$c29tZXNhbHQ\$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"
        )
    }

    @Test
    fun positiveTest13() = runTest {
        hashTest(
            2, 8, 2, "password", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=256,t=2,p=2\$c29tZXNhbHQ\$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc"
        )
    }

    @Test
    fun positiveTest14() = runTest {
        hashTest(
            1, 16, 1, "password", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=65536,t=1,p=1\$c29tZXNhbHQ\$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg"
        )
    }

    @Test
    fun positiveTest15() = runTest {
        hashTest(
            4, 16, 1, "password", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=65536,t=4,p=1\$c29tZXNhbHQ\$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw"
        )
    }

    @Test
    fun positiveTest16() = runTest {
        hashTest(
            2, 16, 1, "differentpassword", "somesalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=65536,t=2,p=1\$c29tZXNhbHQ\$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94"
        )
    }

    @Test
    fun positiveTest17() = runTest {
        hashTest(
            2, 16, 1, "password", "diffsalt", Argon2.Argon2id,
            "\$argon2id\$v=19\$m=65536,t=2,p=1\$ZGlmZnNhbHQ\$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw"
        )
    }

    private suspend fun hashTest(
        iterations: Int,
        memoryAsExponentOf2: Int,
        parallelism: Int,
        messageStr: String,
        saltStr: String,
        type: Argon2.Type,
        expectedResult: String
    ) {
        val memorySizeKB = 2.toDouble().pow(memoryAsExponentOf2).toInt()
        val message = messageStr.encodeToByteArray()
        val salt = saltStr.encodeToByteArray()
        val actualResult = Argon2(32, parallelism, memorySizeKB, iterations, type)
            .hashEncoded(message, salt)
        assertEquals(expectedResult, actualResult)
    }
}