package com.qubee.messenger.data

import android.content.Context
import com.qubee.messenger.BuildConfig
import com.qubee.messenger.crypto.RelayCryptoEngine
import com.qubee.messenger.data.db.QubeeDatabase
import com.qubee.messenger.data.db.SecureDatabaseFactory
import com.qubee.messenger.network.p2p.HybridEnvelopeDispatcher
import com.qubee.messenger.network.p2p.LocalBootstrapTransport
import com.qubee.messenger.network.p2p.RelaySignalingTransport
import com.qubee.messenger.network.p2p.WebRtcEnvelopeTransport
import com.qubee.messenger.network.p2p.WebRtcSwarmCoordinator
import com.qubee.messenger.security.AppKeyManager
import com.qubee.messenger.security.DatabasePassphraseManager
import com.qubee.messenger.transport.DemoRelayTransport
import com.qubee.messenger.transport.RelayTransport
import com.qubee.messenger.transport.WebSocketRelayTransport

class QubeeServiceLocator private constructor(context: Context) {
    private val appContext = context.applicationContext

    val appKeyManager: AppKeyManager by lazy { AppKeyManager(appContext) }
    val databasePassphraseManager: DatabasePassphraseManager by lazy {
        DatabasePassphraseManager(appContext, appKeyManager)
    }
    val cryptoEngine: RelayCryptoEngine by lazy { RelayCryptoEngine() }
    val relayTransport: RelayTransport by lazy {
        if (BuildConfig.DEFAULT_RELAY_URL.startsWith("ws")) WebSocketRelayTransport() else DemoRelayTransport()
    }
    val localBootstrapTransport: LocalBootstrapTransport by lazy { LocalBootstrapTransport(appContext) }
    val webRtcSwarmCoordinator: WebRtcSwarmCoordinator by lazy {
        WebRtcSwarmCoordinator(
            localBootstrapTransport = localBootstrapTransport,
            wanBootstrapTransport = RelaySignalingTransport(relayTransport),
        )
    }
    val webRtcEnvelopeTransport: WebRtcEnvelopeTransport by lazy {
        WebRtcEnvelopeTransport(appContext, webRtcSwarmCoordinator)
    }
    val hybridDispatcher: HybridEnvelopeDispatcher by lazy {
        HybridEnvelopeDispatcher(webRtcEnvelopeTransport, relayTransport)
    }

    @Volatile
    private var databaseRef: QubeeDatabase? = null
    @Volatile
    private var repositoryRef: MessengerRepository? = null

    fun hasExistingVault(): Boolean = appKeyManager.hasMasterKey() || databasePassphraseManager.hasWrappedPassphrase()

    fun unlockRepository(): MessengerRepository {
        appKeyManager.warmUpKeyAccess()
        val database = databaseRef ?: synchronized(this) {
            databaseRef ?: SecureDatabaseFactory.build(appContext, databasePassphraseManager).also { databaseRef = it }
        }
        return repositoryRef ?: synchronized(this) {
            repositoryRef ?: MessengerRepository(
                dao = database.qubeeDao(),
                cryptoEngine = cryptoEngine,
                relayTransport = relayTransport,
                hybridDispatcher = hybridDispatcher,
            ).also { repositoryRef = it }
        }
    }

    companion object {
        @Volatile
        private var instance: QubeeServiceLocator? = null

        fun from(context: Context): QubeeServiceLocator {
            return instance ?: synchronized(this) {
                instance ?: QubeeServiceLocator(context).also { instance = it }
            }
        }
    }
}
