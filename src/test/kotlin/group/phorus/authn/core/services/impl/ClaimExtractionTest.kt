package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.ClaimsMapping
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class ClaimExtractionTest {

    @Nested
    @DisplayName("requireFlatClaimNames")
    inner class RequireFlatClaimNames {

        @Test
        fun `accepts the registered defaults`() {
            requireFlatClaimNames(ClaimsMapping())
        }

        @Test
        fun `rejects a nested roles name and names the offender`() {
            val error = assertThrows<IllegalArgumentException> {
                requireFlatClaimNames(ClaimsMapping(roles = "realm_access.roles"))
            }
            assertEquals(true, error.message!!.contains("roles=realm_access.roles"))
        }

        @Test
        fun `rejects a nested scope name`() {
            assertThrows<IllegalArgumentException> {
                requireFlatClaimNames(ClaimsMapping(scope = "access.scp"))
            }
        }

        @Test
        fun `rejects a nested subject name`() {
            assertThrows<IllegalArgumentException> {
                requireFlatClaimNames(ClaimsMapping(subject = "user.id"))
            }
        }
    }
}
