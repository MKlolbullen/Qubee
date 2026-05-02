package com.qubee.messenger.identity

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.google.gson.annotations.SerializedName

/**
 * JSON-shaped envelope returned by the Rust JNI for hybrid-signed
 * onboarding (not ZK — the bundle is signed by the advertised
 * Ed25519+Dilithium identity and verifiers re-derive the canonical
 * bytes to check it).
 *
 * The private key material never leaves Rust; this class only carries
 * the public identity, the verifier-friendly fingerprint, and the
 * `qubee://identity/...` share link suitable for QR codes.
 */
data class IdentityBundle(
    @SerializedName("user_id") val userId: String,
    @SerializedName("display_name") val displayName: String,
    @SerializedName("identity_id_hex") val identityIdHex: String,
    @SerializedName("fingerprint") val fingerprint: String,
    @SerializedName("share_link") val shareLink: String? = null,
    @SerializedName("max_group_members") val maxGroupMembers: Int? = null,
) {
    companion object {
        private val gson = Gson()

        fun fromJson(json: String?): IdentityBundle? {
            if (json.isNullOrBlank()) return null
            return try {
                gson.fromJson(json, IdentityBundle::class.java)
            } catch (e: JsonSyntaxException) {
                null
            }
        }
    }
}
