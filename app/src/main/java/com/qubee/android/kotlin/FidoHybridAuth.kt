class FidoHybridAuth(
    private val activity: Activity,
    private val crypto: CryptoManager = CryptoManager
) {
    fun startAuthentication() {
        // 1. Trigger Android FIDO2 API
        val options = PublicKeyCredentialRequestOptions.Builder()
            .setChallenge(crypto.generateKeyPair().public) // use PQ public as challenge
            .build()

        val fidoClient = Fido.getFido2ApiClient(activity)
        fidoClient.getSignIntent(options).addOnSuccessListener { intent ->
            activity.startIntentSenderForResult(
              intent.intentSender, REQUEST_FIDO2_SIGN, null, 0, 0, 0, null
            )
        }
    }

    // Called from Activity.onActivityResult
    fun handleFidoResult(data: Intent?) {
        val response = AuthenticatorAssertionResponse.deserializeFromBytes(
            data!!.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)!!
        )
        // Combine FIDO2 signature + PQ signature for a hybrid proof
        val pqSig = crypto.sign(response.clientDataJSON, crypto.generateKeyPair().private)
        // Send (fidoSig, pqSig, clientDataJSON) to server
    }

    companion object { private const val REQUEST_FIDO2_SIGN = 42 }
}
