package com.qubee.messenger.di

import android.content.Context
import com.qubee.messenger.data.repository.database.QubeeDatabase
import com.qubee.messenger.data.repository.database.dao.ContactDao
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.CryptoKeyDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import com.qubee.messenger.security.SqlCipherKeyProvider
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideSqlCipherKeyProvider(
        @ApplicationContext context: Context,
    ): SqlCipherKeyProvider = SqlCipherKeyProvider(context)

    @Provides
    @Singleton
    fun provideQubeeDatabase(
        @ApplicationContext context: Context,
        keyProvider: SqlCipherKeyProvider,
    ): QubeeDatabase = QubeeDatabase.getInstance(context, keyProvider)

    @Provides
    fun provideContactDao(database: QubeeDatabase): ContactDao = database.contactDao()

    @Provides
    fun provideConversationDao(database: QubeeDatabase): ConversationDao =
        database.conversationDao()

    @Provides
    fun provideMessageDao(database: QubeeDatabase): MessageDao = database.messageDao()

    @Provides
    fun provideCryptoKeyDao(database: QubeeDatabase): CryptoKeyDao = database.cryptoKeyDao()
}
