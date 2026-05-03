package com.qubee.messenger.di

import android.content.Context
import com.qubee.messenger.data.repository.database.QubeeDatabase
import com.qubee.messenger.data.repository.database.dao.ContactDao
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.CryptoKeyDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

// First-and-only Hilt module in the project. The `@Inject`-constructed
// Repositories upstream depended on these `@Provides` for the DAOs
// the entire time the project's been alive — they just weren't
// wired, which is why every previous attempt to actually start the
// app exploded inside Hilt's generated component code (no
// implementation found for ContactDao / MessageDao / etc.). Rev-3
// closes that gap.
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideQubeeDatabase(@ApplicationContext context: Context): QubeeDatabase =
        QubeeDatabase.getInstance(context)

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
