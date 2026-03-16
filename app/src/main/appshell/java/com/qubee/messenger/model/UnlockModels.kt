package com.qubee.messenger.model

enum class VaultLockState {
    Locked,
    Unlocking,
    Unlocked,
    Error,
}

data class VaultStatus(
    val state: VaultLockState = VaultLockState.Locked,
    val details: String = "Secure vault locked.",
    val hasExistingVault: Boolean = false,
)
