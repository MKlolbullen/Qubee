class DidResolver {
  suspend fun resolve(did: String): DidDocument {
    val url = "https://uniresolver.io/1.0/identifiers/$did"
    val json = httpClient.get<String>(url)
    return jsonAdapter.fromJson(json)!!
  }
}
