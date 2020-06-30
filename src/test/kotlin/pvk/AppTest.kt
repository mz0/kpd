package pvk

import kotlin.test.Test
import kotlin.test.assertNotNull

class AppTest {
    @Test fun testAppHasVersion() {
        val classUnderTest = App()
        assertNotNull(classUnderTest.version, "app should have a version string")
    }
}
