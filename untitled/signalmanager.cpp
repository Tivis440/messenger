#include "signalmanager.h"

#include <QDateTime>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QUrl>

#ifdef Q_OS_MACOS
#include <Security/Security.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <signal/curve.h>
#include <signal/key_helper.h>
#include <signal/protocol.h>
#include <signal/session_builder.h>
#include <signal/session_cipher.h>
#include <signal/session_pre_key.h>
#include <signal/signal_protocol.h>

static constexpr int STATE_KEY_BYTES = 32;
static constexpr int STATE_NONCE_BYTES = 12;
static constexpr int STATE_TAG_BYTES = 16;
static const char *STATE_ENCRYPTION_ALGORITHM = "aes-256-gcm";
static const char *SECURE_KEY_SERVICE = "com.local.qt-messenger.signal-state";

static int cryptoRandom(uint8_t *data, size_t len, void *)
{
    return RAND_bytes(data, static_cast<int>(len)) == 1 ? SG_SUCCESS : SG_ERR_UNKNOWN;
}

static int hmacInit(void **ctxOut, const uint8_t *key, size_t keyLen, void *)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx)
        return SG_ERR_NOMEM;
    if (HMAC_Init_ex(ctx, key, static_cast<int>(keyLen), EVP_sha256(), nullptr) != 1)
        return SG_ERR_UNKNOWN;
    *ctxOut = ctx;
    return SG_SUCCESS;
}

static int hmacUpdate(void *ctx, const uint8_t *data, size_t len, void *)
{
    return HMAC_Update(static_cast<HMAC_CTX *>(ctx), data, len) == 1 ? SG_SUCCESS : SG_ERR_UNKNOWN;
}

static int hmacFinal(void *ctx, signal_buffer **output, void *)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (HMAC_Final(static_cast<HMAC_CTX *>(ctx), md, &len) != 1)
        return SG_ERR_UNKNOWN;
    *output = signal_buffer_create(md, len);
    return *output ? SG_SUCCESS : SG_ERR_NOMEM;
}

static void hmacCleanup(void *ctx, void *)
{
    HMAC_CTX_free(static_cast<HMAC_CTX *>(ctx));
}

#ifdef Q_OS_MACOS
static CFStringRef createCFString(const QByteArray &value)
{
    return CFStringCreateWithBytes(kCFAllocatorDefault,
                                   reinterpret_cast<const UInt8 *>(value.constData()),
                                   value.size(),
                                   kCFStringEncodingUTF8,
                                   false);
}

static QByteArray secureKeyAccountForUser(const QString &username)
{
    return "signal-state:" + QUrl::toPercentEncoding(username);
}

static void setKeychainIdentity(CFMutableDictionaryRef query, const QByteArray &accountBytes)
{
    CFStringRef service = createCFString(QByteArray(SECURE_KEY_SERVICE));
    CFStringRef account = createCFString(accountBytes);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service);
    CFDictionarySetValue(query, kSecAttrAccount, account);
    CFRelease(service);
    CFRelease(account);
}

static bool copySecureStateKey(const QString &username, QByteArray *key)
{
    const QByteArray accountBytes = secureKeyAccountForUser(username);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                             0,
                                                             &kCFTypeDictionaryKeyCallBacks,
                                                             &kCFTypeDictionaryValueCallBacks);
    setKeychainIdentity(query, accountBytes);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = nullptr;
    const OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess || !result)
        return false;

    CFDataRef data = static_cast<CFDataRef>(result);
    *key = QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)), CFDataGetLength(data));
    CFRelease(result);
    return key->size() == STATE_KEY_BYTES;
}

static bool getOrCreateSecureStateKey(const QString &username, QByteArray *key)
{
    if (copySecureStateKey(username, key))
        return true;

    key->resize(STATE_KEY_BYTES);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(key->data()), key->size()) != 1)
        return false;

    const QByteArray accountBytes = secureKeyAccountForUser(username);
    CFMutableDictionaryRef item = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                            0,
                                                            &kCFTypeDictionaryKeyCallBacks,
                                                            &kCFTypeDictionaryValueCallBacks);
    setKeychainIdentity(item, accountBytes);
    CFDataRef secret = CFDataCreate(kCFAllocatorDefault,
                                    reinterpret_cast<const UInt8 *>(key->constData()),
                                    key->size());
    CFDictionarySetValue(item, kSecValueData, secret);
    CFDictionarySetValue(item, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);

    OSStatus status = SecItemAdd(item, nullptr);
    CFRelease(secret);
    CFRelease(item);

    if (status == errSecDuplicateItem)
        return copySecureStateKey(username, key);

    return status == errSecSuccess;
}

static QString secureStateKeyStoreName()
{
    return "macOS Keychain";
}
#else
static bool getOrCreateSecureStateKey(const QString &, QByteArray *)
{
    return false;
}

static QString secureStateKeyStoreName()
{
    return "Unavailable";
}
#endif

static bool encryptStatePayload(const QString &username, const QByteArray &plainText, QJsonObject *encryptedRoot)
{
    QByteArray key;
    if (!getOrCreateSecureStateKey(username, &key))
        return false;

    QByteArray nonce(STATE_NONCE_BYTES, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(nonce.data()), nonce.size()) != 1)
        return false;

    QByteArray cipherText(plainText.size(), Qt::Uninitialized);
    QByteArray tag(STATE_TAG_BYTES, Qt::Uninitialized);
    int outLen = 0;
    int totalLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx,
                                 nullptr,
                                 nullptr,
                                 reinterpret_cast<const unsigned char *>(key.constData()),
                                 reinterpret_cast<const unsigned char *>(nonce.constData())) == 1 &&
              EVP_EncryptUpdate(ctx,
                                reinterpret_cast<unsigned char *>(cipherText.data()),
                                &outLen,
                                reinterpret_cast<const unsigned char *>(plainText.constData()),
                                plainText.size()) == 1;
    totalLen = outLen;

    if (ok)
        ok = EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char *>(cipherText.data()) + totalLen,
                                 &outLen) == 1;
    totalLen += outLen;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) == 1;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
        return false;

    cipherText.truncate(totalLen);
    encryptedRoot->insert("version", 2);
    encryptedRoot->insert("encrypted", true);
    encryptedRoot->insert("algorithm", STATE_ENCRYPTION_ALGORITHM);
    encryptedRoot->insert("keyStore", secureStateKeyStoreName());
    encryptedRoot->insert("nonce", QString::fromLatin1(nonce.toBase64()));
    encryptedRoot->insert("tag", QString::fromLatin1(tag.toBase64()));
    encryptedRoot->insert("ciphertext", QString::fromLatin1(cipherText.toBase64()));
    return true;
}

static bool decryptStatePayload(const QString &username, const QJsonObject &encryptedRoot, QByteArray *plainText)
{
    if (encryptedRoot.value("algorithm").toString() != STATE_ENCRYPTION_ALGORITHM)
        return false;

    QByteArray key;
    if (!getOrCreateSecureStateKey(username, &key))
        return false;

    const QByteArray nonce = QByteArray::fromBase64(encryptedRoot.value("nonce").toString().toLatin1());
    const QByteArray tag = QByteArray::fromBase64(encryptedRoot.value("tag").toString().toLatin1());
    const QByteArray cipherText = QByteArray::fromBase64(encryptedRoot.value("ciphertext").toString().toLatin1());
    if (nonce.size() != STATE_NONCE_BYTES || tag.size() != STATE_TAG_BYTES || cipherText.isEmpty())
        return false;

    QByteArray output(cipherText.size(), Qt::Uninitialized);
    int outLen = 0;
    int totalLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx,
                                 nullptr,
                                 nullptr,
                                 reinterpret_cast<const unsigned char *>(key.constData()),
                                 reinterpret_cast<const unsigned char *>(nonce.constData())) == 1 &&
              EVP_DecryptUpdate(ctx,
                                reinterpret_cast<unsigned char *>(output.data()),
                                &outLen,
                                reinterpret_cast<const unsigned char *>(cipherText.constData()),
                                cipherText.size()) == 1;
    totalLen = outLen;

    if (ok)
    {
        ok = EVP_CIPHER_CTX_ctrl(ctx,
                                 EVP_CTRL_GCM_SET_TAG,
                                 tag.size(),
                                 const_cast<char *>(tag.constData())) == 1 &&
             EVP_DecryptFinal_ex(ctx,
                                  reinterpret_cast<unsigned char *>(output.data()) + totalLen,
                                  &outLen) == 1;
    }
    totalLen += outLen;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
        return false;

    output.truncate(totalLen);
    *plainText = output;
    return true;
}

static int sha512Init(void **ctxOut, void *)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return SG_ERR_NOMEM;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1)
        return SG_ERR_UNKNOWN;
    *ctxOut = ctx;
    return SG_SUCCESS;
}

static int sha512Update(void *ctx, const uint8_t *data, size_t len, void *)
{
    return EVP_DigestUpdate(static_cast<EVP_MD_CTX *>(ctx), data, len) == 1 ? SG_SUCCESS : SG_ERR_UNKNOWN;
}

static int sha512Final(void *ctx, signal_buffer **output, void *)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *digest = static_cast<EVP_MD_CTX *>(ctx);
    if (EVP_DigestFinal_ex(digest, md, &len) != 1)
        return SG_ERR_UNKNOWN;
    if (EVP_DigestInit_ex(digest, EVP_sha512(), nullptr) != 1)
        return SG_ERR_UNKNOWN;
    *output = signal_buffer_create(md, len);
    return *output ? SG_SUCCESS : SG_ERR_NOMEM;
}

static void sha512Cleanup(void *ctx, void *)
{
    EVP_MD_CTX_free(static_cast<EVP_MD_CTX *>(ctx));
}

static const EVP_CIPHER *aesCipher(int cipher, size_t keyLen)
{
    if (cipher == SG_CIPHER_AES_CBC_PKCS5)
        return keyLen == 16 ? EVP_aes_128_cbc() : keyLen == 24 ? EVP_aes_192_cbc() : keyLen == 32 ? EVP_aes_256_cbc() : nullptr;
    if (cipher == SG_CIPHER_AES_CTR_NOPADDING)
        return keyLen == 16 ? EVP_aes_128_ctr() : keyLen == 24 ? EVP_aes_192_ctr() : keyLen == 32 ? EVP_aes_256_ctr() : nullptr;
    return nullptr;
}

static int aesCrypt(bool encrypt, signal_buffer **output, int cipher, const uint8_t *key, size_t keyLen, const uint8_t *iv, size_t ivLen, const uint8_t *input, size_t inputLen)
{
    const EVP_CIPHER *evp = aesCipher(cipher, keyLen);
    if (!evp || ivLen != 16)
        return SG_ERR_INVAL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SG_ERR_NOMEM;

    QByteArray out;
    out.resize(static_cast<int>(inputLen + EVP_CIPHER_block_size(evp)));

    int ok = encrypt ? EVP_EncryptInit_ex(ctx, evp, nullptr, key, iv) : EVP_DecryptInit_ex(ctx, evp, nullptr, key, iv);
    if (ok == 1 && cipher == SG_CIPHER_AES_CTR_NOPADDING)
        ok = EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outLen = 0;
    int finalLen = 0;
    if (ok == 1)
        ok = encrypt ? EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(out.data()), &outLen, input, static_cast<int>(inputLen))
                     : EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(out.data()), &outLen, input, static_cast<int>(inputLen));
    if (ok == 1)
        ok = encrypt ? EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(out.data()) + outLen, &finalLen)
                     : EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(out.data()) + outLen, &finalLen);

    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1)
        return SG_ERR_UNKNOWN;

    *output = signal_buffer_create(reinterpret_cast<const uint8_t *>(out.constData()), outLen + finalLen);
    return *output ? SG_SUCCESS : SG_ERR_NOMEM;
}

static int cryptoEncrypt(signal_buffer **output, int cipher, const uint8_t *key, size_t keyLen, const uint8_t *iv, size_t ivLen, const uint8_t *plaintext, size_t plaintextLen, void *)
{
    return aesCrypt(true, output, cipher, key, keyLen, iv, ivLen, plaintext, plaintextLen);
}

static int cryptoDecrypt(signal_buffer **output, int cipher, const uint8_t *key, size_t keyLen, const uint8_t *iv, size_t ivLen, const uint8_t *ciphertext, size_t ciphertextLen, void *)
{
    return aesCrypt(false, output, cipher, key, keyLen, iv, ivLen, ciphertext, ciphertextLen);
}

QString SignalProtocolManager::addressKey(const char *name, size_t nameLen, int deviceId)
{
    return QString::fromUtf8(name, static_cast<int>(nameLen)) + ":" + QString::number(deviceId);
}

QByteArray SignalProtocolManager::bufferToByteArray(signal_buffer *buffer)
{
    if (!buffer)
        return {};
    return QByteArray(reinterpret_cast<const char *>(signal_buffer_const_data(buffer)), static_cast<int>(signal_buffer_len(buffer)));
}

QString SignalProtocolManager::toBase64(const QByteArray &data)
{
    return QString::fromLatin1(data.toBase64());
}

QByteArray SignalProtocolManager::fromBase64(const QJsonObject &object, const QString &key)
{
    return QByteArray::fromBase64(object.value(key).toString().toLatin1());
}

static int loadSession(signal_buffer **record, signal_buffer **, const signal_protocol_address *address, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    const QByteArray data = store->sessions.value(SignalProtocolManager::addressKey(address->name, address->name_len, address->device_id));
    if (data.isEmpty())
        return 0;
    *record = signal_buffer_create(reinterpret_cast<const uint8_t *>(data.constData()), data.size());
    return *record ? 1 : SG_ERR_NOMEM;
}

static int getSubDeviceSessions(signal_int_list **sessions, const char *name, size_t nameLen, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    signal_int_list *list = signal_int_list_alloc();
    if (!list)
        return SG_ERR_NOMEM;
    const QString prefix = QString::fromUtf8(name, static_cast<int>(nameLen)) + ":";
    for (auto it = store->sessions.begin(); it != store->sessions.end(); ++it)
        if (it.key().startsWith(prefix))
            signal_int_list_push_back(list, it.key().mid(prefix.size()).toInt());
    *sessions = list;
    return SG_SUCCESS;
}

static int storeSession(const signal_protocol_address *address, uint8_t *record, size_t recordLen, uint8_t *, size_t, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    store->sessions.insert(SignalProtocolManager::addressKey(address->name, address->name_len, address->device_id), QByteArray(reinterpret_cast<const char *>(record), recordLen));
    return SG_SUCCESS;
}

static int containsSession(const signal_protocol_address *address, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    return store->sessions.contains(SignalProtocolManager::addressKey(address->name, address->name_len, address->device_id)) ? 1 : 0;
}

static int deleteSession(const signal_protocol_address *address, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    return store->sessions.remove(SignalProtocolManager::addressKey(address->name, address->name_len, address->device_id));
}

static int deleteAllSessions(const char *name, size_t nameLen, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    const QString prefix = QString::fromUtf8(name, static_cast<int>(nameLen)) + ":";
    int count = 0;
    for (const QString &key : store->sessions.keys())
        if (key.startsWith(prefix))
            count += store->sessions.remove(key);
    return count;
}

static int loadPreKey(signal_buffer **record, uint32_t id, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    const QByteArray data = store->preKeys.value(id);
    if (data.isEmpty())
        return SG_ERR_INVALID_KEY_ID;
    *record = signal_buffer_create(reinterpret_cast<const uint8_t *>(data.constData()), data.size());
    return *record ? SG_SUCCESS : SG_ERR_NOMEM;
}

static int storePreKey(uint32_t id, uint8_t *record, size_t len, void *userData)
{
    static_cast<SignalProtocolManager::StoreData *>(userData)->preKeys.insert(id, QByteArray(reinterpret_cast<const char *>(record), len));
    return SG_SUCCESS;
}

static int containsPreKey(uint32_t id, void *userData)
{
    return static_cast<SignalProtocolManager::StoreData *>(userData)->preKeys.contains(id) ? 1 : 0;
}

static int removePreKey(uint32_t id, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    store->preKeys.remove(id);
    if (store->owner)
        store->owner->removePublishedPreKey(id);
    return SG_SUCCESS;
}

static int loadSignedPreKey(signal_buffer **record, uint32_t id, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    const QByteArray data = store->signedPreKeys.value(id);
    if (data.isEmpty())
        return SG_ERR_INVALID_KEY_ID;
    *record = signal_buffer_create(reinterpret_cast<const uint8_t *>(data.constData()), data.size());
    return *record ? SG_SUCCESS : SG_ERR_NOMEM;
}

static int storeSignedPreKey(uint32_t id, uint8_t *record, size_t len, void *userData)
{
    static_cast<SignalProtocolManager::StoreData *>(userData)->signedPreKeys.insert(id, QByteArray(reinterpret_cast<const char *>(record), len));
    return SG_SUCCESS;
}

static int containsSignedPreKey(uint32_t id, void *userData)
{
    return static_cast<SignalProtocolManager::StoreData *>(userData)->signedPreKeys.contains(id) ? 1 : 0;
}

static int removeSignedPreKey(uint32_t id, void *userData)
{
    static_cast<SignalProtocolManager::StoreData *>(userData)->signedPreKeys.remove(id);
    return SG_SUCCESS;
}

static int getIdentityKeyPair(signal_buffer **publicData, signal_buffer **privateData, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    *publicData = signal_buffer_create(reinterpret_cast<const uint8_t *>(store->identityPublic.constData()), store->identityPublic.size());
    *privateData = signal_buffer_create(reinterpret_cast<const uint8_t *>(store->identityPrivate.constData()), store->identityPrivate.size());
    return (*publicData && *privateData) ? SG_SUCCESS : SG_ERR_NOMEM;
}

static int getRegistrationId(void *userData, uint32_t *registrationId)
{
    *registrationId = static_cast<SignalProtocolManager::StoreData *>(userData)->registrationId;
    return SG_SUCCESS;
}

static int saveIdentity(const signal_protocol_address *address, uint8_t *keyData, size_t keyLen, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    store->identities.insert(SignalProtocolManager::addressKey(address->name, address->name_len, address->device_id), QByteArray(reinterpret_cast<const char *>(keyData), keyLen));
    return SG_SUCCESS;
}

static int isTrustedIdentity(const signal_protocol_address *address, uint8_t *keyData, size_t keyLen, void *userData)
{
    auto *store = static_cast<SignalProtocolManager::StoreData *>(userData);
    const QByteArray saved = store->identities.value(SignalProtocolManager::addressKey(address->name, address->name_len, address->device_id));
    return saved.isEmpty() || saved == QByteArray(reinterpret_cast<const char *>(keyData), keyLen) ? 1 : 0;
}

SignalProtocolManager::SignalProtocolManager() = default;

SignalProtocolManager::~SignalProtocolManager()
{
    cleanup();
}

bool SignalProtocolManager::initialize(const QString &username)
{
    cleanup();
    m_username = username;
    m_store = new StoreData;
    m_store->owner = this;
    if (!setupContexts())
        return false;
    if (loadState())
        return true;
    return generateLocalKeys();
}

bool SignalProtocolManager::setupContexts()
{
    if (signal_context_create(&m_context, this) != SG_SUCCESS)
        return false;

    signal_crypto_provider provider{};
    provider.random_func = cryptoRandom;
    provider.hmac_sha256_init_func = hmacInit;
    provider.hmac_sha256_update_func = hmacUpdate;
    provider.hmac_sha256_final_func = hmacFinal;
    provider.hmac_sha256_cleanup_func = hmacCleanup;
    provider.sha512_digest_init_func = sha512Init;
    provider.sha512_digest_update_func = sha512Update;
    provider.sha512_digest_final_func = sha512Final;
    provider.sha512_digest_cleanup_func = sha512Cleanup;
    provider.encrypt_func = cryptoEncrypt;
    provider.decrypt_func = cryptoDecrypt;
    signal_context_set_crypto_provider(m_context, &provider);

    if (signal_protocol_store_context_create(&m_storeContext, m_context) != SG_SUCCESS)
        return false;

    signal_protocol_session_store sessionStore{};
    sessionStore.load_session_func = loadSession;
    sessionStore.get_sub_device_sessions_func = getSubDeviceSessions;
    sessionStore.store_session_func = storeSession;
    sessionStore.contains_session_func = containsSession;
    sessionStore.delete_session_func = deleteSession;
    sessionStore.delete_all_sessions_func = deleteAllSessions;
    sessionStore.user_data = m_store;
    signal_protocol_store_context_set_session_store(m_storeContext, &sessionStore);

    signal_protocol_pre_key_store preKeyStore{};
    preKeyStore.load_pre_key = loadPreKey;
    preKeyStore.store_pre_key = storePreKey;
    preKeyStore.contains_pre_key = containsPreKey;
    preKeyStore.remove_pre_key = removePreKey;
    preKeyStore.user_data = m_store;
    signal_protocol_store_context_set_pre_key_store(m_storeContext, &preKeyStore);

    signal_protocol_signed_pre_key_store signedStore{};
    signedStore.load_signed_pre_key = loadSignedPreKey;
    signedStore.store_signed_pre_key = storeSignedPreKey;
    signedStore.contains_signed_pre_key = containsSignedPreKey;
    signedStore.remove_signed_pre_key = removeSignedPreKey;
    signedStore.user_data = m_store;
    signal_protocol_store_context_set_signed_pre_key_store(m_storeContext, &signedStore);

    signal_protocol_identity_key_store identityStore{};
    identityStore.get_identity_key_pair = getIdentityKeyPair;
    identityStore.get_local_registration_id = getRegistrationId;
    identityStore.save_identity = saveIdentity;
    identityStore.is_trusted_identity = isTrustedIdentity;
    identityStore.user_data = m_store;
    signal_protocol_store_context_set_identity_key_store(m_storeContext, &identityStore);
    return true;
}

bool SignalProtocolManager::generateLocalKeys()
{
    ratchet_identity_key_pair *identity = nullptr;
    if (signal_protocol_key_helper_generate_identity_key_pair(&identity, m_context) != SG_SUCCESS)
        return false;

    signal_buffer *identityPub = nullptr;
    signal_buffer *identityPriv = nullptr;
    ec_public_key_serialize(&identityPub, ratchet_identity_key_pair_get_public(identity));
    ec_private_key_serialize(&identityPriv, ratchet_identity_key_pair_get_private(identity));
    m_store->identityPublic = bufferToByteArray(identityPub);
    m_store->identityPrivate = bufferToByteArray(identityPriv);
    signal_buffer_free(identityPub);
    signal_buffer_free(identityPriv);

    uint32_t registrationId = 0;
    signal_protocol_key_helper_generate_registration_id(&registrationId, 0, m_context);
    m_store->registrationId = registrationId;

    QJsonArray publicPreKeys;
    signal_protocol_key_helper_pre_key_list_node *preKeys = nullptr;
    signal_protocol_key_helper_generate_pre_keys(&preKeys, 1, 50, m_context);
    for (signal_protocol_key_helper_pre_key_list_node *node = preKeys; node; node = signal_protocol_key_helper_key_list_next(node))
    {
        session_pre_key *preKey = signal_protocol_key_helper_key_list_element(node);
        signal_buffer *preKeyRecord = nullptr;
        signal_buffer *preKeyPublic = nullptr;
        session_pre_key_serialize(&preKeyRecord, preKey);
        ec_public_key_serialize(&preKeyPublic, ec_key_pair_get_public(session_pre_key_get_key_pair(preKey)));
        m_store->preKeys.insert(session_pre_key_get_id(preKey), bufferToByteArray(preKeyRecord));

        QJsonObject publicPreKey;
        publicPreKey.insert("id", static_cast<int>(session_pre_key_get_id(preKey)));
        publicPreKey.insert("public", toBase64(bufferToByteArray(preKeyPublic)));
        publicPreKeys.append(publicPreKey);
        signal_buffer_free(preKeyRecord);
        signal_buffer_free(preKeyPublic);
    }

    session_signed_pre_key *signedPreKey = nullptr;
    signal_protocol_key_helper_generate_signed_pre_key(&signedPreKey, identity, 1, QDateTime::currentMSecsSinceEpoch(), m_context);
    signal_buffer *signedRecord = nullptr;
    signal_buffer *signedPublic = nullptr;
    session_signed_pre_key_serialize(&signedRecord, signedPreKey);
    ec_public_key_serialize(&signedPublic, ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signedPreKey)));
    m_store->signedPreKeys.insert(session_signed_pre_key_get_id(signedPreKey), bufferToByteArray(signedRecord));

    m_localBundle.insert("registrationId", static_cast<int>(m_store->registrationId));
    m_localBundle.insert("deviceId", 1);
    m_localBundle.insert("preKeys", publicPreKeys);
    m_localBundle.insert("signedPreKeyId", static_cast<int>(session_signed_pre_key_get_id(signedPreKey)));
    m_localBundle.insert("signedPreKeyPublic", toBase64(bufferToByteArray(signedPublic)));
    m_localBundle.insert("signedPreKeySignature", toBase64(QByteArray(reinterpret_cast<const char *>(session_signed_pre_key_get_signature(signedPreKey)), session_signed_pre_key_get_signature_len(signedPreKey))));
    m_localBundle.insert("identityKey", toBase64(m_store->identityPublic));

    signal_buffer_free(signedRecord);
    signal_buffer_free(signedPublic);
    signal_protocol_key_helper_key_list_free(preKeys);
    SIGNAL_UNREF(signedPreKey);
    SIGNAL_UNREF(identity);
    saveState();
    return true;
}

QString SignalProtocolManager::localPreKeyBundleJson() const
{
    return QString::fromUtf8(QJsonDocument(m_localBundle).toJson(QJsonDocument::Compact));
}

bool SignalProtocolManager::hasSession(const QString &peer) const
{
    return m_store && m_store->sessions.contains(peer + ":1");
}

bool SignalProtocolManager::processPreKeyBundle(const QString &peer, const QString &bundleJson)
{
    const QJsonObject object = QJsonDocument::fromJson(bundleJson.toUtf8()).object();
    if (object.isEmpty())
        return false;

    ec_public_key *preKey = nullptr;
    ec_public_key *signedPreKey = nullptr;
    ec_public_key *identityKey = nullptr;
    const QByteArray preKeyBytes = fromBase64(object, "preKeyPublic");
    const QByteArray signedBytes = fromBase64(object, "signedPreKeyPublic");
    const QByteArray identityBytes = fromBase64(object, "identityKey");
    const QByteArray signature = fromBase64(object, "signedPreKeySignature");

    if (curve_decode_point(&preKey, reinterpret_cast<const uint8_t *>(preKeyBytes.constData()), preKeyBytes.size(), m_context) != SG_SUCCESS)
        return false;
    if (curve_decode_point(&signedPreKey, reinterpret_cast<const uint8_t *>(signedBytes.constData()), signedBytes.size(), m_context) != SG_SUCCESS)
        return false;
    if (curve_decode_point(&identityKey, reinterpret_cast<const uint8_t *>(identityBytes.constData()), identityBytes.size(), m_context) != SG_SUCCESS)
        return false;

    session_pre_key_bundle *bundle = nullptr;
    int result = session_pre_key_bundle_create(&bundle,
                                               object.value("registrationId").toInt(),
                                               object.value("deviceId").toInt(1),
                                               object.value("preKeyId").toInt(),
                                               preKey,
                                               object.value("signedPreKeyId").toInt(),
                                               signedPreKey,
                                               reinterpret_cast<const uint8_t *>(signature.constData()),
                                               signature.size(),
                                               identityKey);
    if (result != SG_SUCCESS)
        return false;

    const QByteArray peerName = peer.toUtf8();
    signal_protocol_address address{peerName.constData(), static_cast<size_t>(peerName.size()), 1};
    session_builder *builder = nullptr;
    result = session_builder_create(&builder, m_storeContext, &address, m_context);
    if (result == SG_SUCCESS)
        result = session_builder_process_pre_key_bundle(builder, bundle);

    if (builder)
        session_builder_free(builder);
    SIGNAL_UNREF(bundle);
    if (result == SG_SUCCESS)
        saveState();
    return result == SG_SUCCESS;
}

bool SignalProtocolManager::encrypt(const QString &peer, const QString &plainText, QString *wirePayload, QString *error)
{
    const QByteArray peerName = peer.toUtf8();
    signal_protocol_address address{peerName.constData(), static_cast<size_t>(peerName.size()), 1};
    session_cipher *cipher = nullptr;
    int result = session_cipher_create(&cipher, m_storeContext, &address, m_context);
    if (result != SG_SUCCESS)
    {
        if (error)
            *error = "Не удалось создать Signal cipher";
        return false;
    }

    ciphertext_message *encrypted = nullptr;
    const QByteArray plain = plainText.toUtf8();
    result = session_cipher_encrypt(cipher, reinterpret_cast<const uint8_t *>(plain.constData()), plain.size(), &encrypted);
    session_cipher_free(cipher);
    if (result != SG_SUCCESS)
    {
        if (error)
            *error = "Signal encryption failed";
        return false;
    }

    signal_buffer *serialized = ciphertext_message_get_serialized(encrypted);
    QJsonObject payload;
    payload.insert("signal", true);
    payload.insert("type", ciphertext_message_get_type(encrypted));
    payload.insert("body", toBase64(bufferToByteArray(serialized)));
    *wirePayload = QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact));
    SIGNAL_UNREF(encrypted);
    saveState();
    return true;
}

bool SignalProtocolManager::decrypt(const QString &peer, const QString &wirePayload, QString *plainText, QString *error)
{
    const QJsonObject payload = QJsonDocument::fromJson(wirePayload.toUtf8()).object();
    if (!payload.value("signal").toBool())
    {
        *plainText = wirePayload;
        return true;
    }

    const QByteArray body = fromBase64(payload, "body");
    const QByteArray peerName = peer.toUtf8();
    signal_protocol_address address{peerName.constData(), static_cast<size_t>(peerName.size()), 1};
    session_cipher *cipher = nullptr;
    int result = session_cipher_create(&cipher, m_storeContext, &address, m_context);
    if (result != SG_SUCCESS)
        return false;

    signal_buffer *plain = nullptr;
    if (payload.value("type").toInt() == CIPHERTEXT_PREKEY_TYPE)
    {
        pre_key_signal_message *message = nullptr;
        result = pre_key_signal_message_deserialize(&message, reinterpret_cast<const uint8_t *>(body.constData()), body.size(), m_context);
        if (result == SG_SUCCESS)
            result = session_cipher_decrypt_pre_key_signal_message(cipher, message, nullptr, &plain);
        if (message)
            SIGNAL_UNREF(message);
    }
    else
    {
        signal_message *message = nullptr;
        result = signal_message_deserialize(&message, reinterpret_cast<const uint8_t *>(body.constData()), body.size(), m_context);
        if (result == SG_SUCCESS)
            result = session_cipher_decrypt_signal_message(cipher, message, nullptr, &plain);
        if (message)
            SIGNAL_UNREF(message);
    }
    session_cipher_free(cipher);

    if (result != SG_SUCCESS || !plain)
    {
        if (error)
            *error = "Signal decryption failed";
        return false;
    }

    *plainText = QString::fromUtf8(reinterpret_cast<const char *>(signal_buffer_const_data(plain)), signal_buffer_len(plain));
    signal_buffer_free(plain);
    saveState();
    return true;
}

QString SignalProtocolManager::identityFingerprint(const QString &peer) const
{
    if (!m_store)
        return QString();

    const QByteArray identity = peer.isEmpty()
                                    ? m_store->identityPublic
                                    : m_store->identities.value(peer + ":1");
    if (identity.isEmpty())
        return QString();

    const QByteArray digest = QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex().toUpper();
    QStringList groups;
    for (int i = 0; i < digest.size() && i < 40; i += 4)
        groups.append(QString::fromLatin1(digest.mid(i, 4)));
    return groups.join(' ');
}

void SignalProtocolManager::removePublishedPreKey(quint32 id)
{
    QJsonArray preKeys = m_localBundle.value("preKeys").toArray();
    QJsonArray remaining;
    for (const QJsonValue &value : preKeys)
    {
        const QJsonObject object = value.toObject();
        if (static_cast<quint32>(object.value("id").toInt()) != id)
            remaining.append(object);
    }

    m_localBundle.insert("preKeys", remaining);
}

static QJsonObject byteMapToJson(const QHash<QString, QByteArray> &map)
{
    QJsonObject object;
    for (auto it = map.begin(); it != map.end(); ++it)
        object.insert(it.key(), SignalProtocolManager::toBase64(it.value()));
    return object;
}

static QJsonObject keyMapToJson(const QHash<quint32, QByteArray> &map)
{
    QJsonObject object;
    for (auto it = map.begin(); it != map.end(); ++it)
        object.insert(QString::number(it.key()), SignalProtocolManager::toBase64(it.value()));
    return object;
}

static QHash<QString, QByteArray> jsonToByteMap(const QJsonObject &object)
{
    QHash<QString, QByteArray> map;
    for (auto it = object.begin(); it != object.end(); ++it)
        map.insert(it.key(), QByteArray::fromBase64(it.value().toString().toLatin1()));
    return map;
}

static QHash<quint32, QByteArray> jsonToKeyMap(const QJsonObject &object)
{
    QHash<quint32, QByteArray> map;
    for (auto it = object.begin(); it != object.end(); ++it)
        map.insert(it.key().toUInt(), QByteArray::fromBase64(it.value().toString().toLatin1()));
    return map;
}

bool SignalProtocolManager::loadState()
{
    QFile file(stateFilePath());
    if (!file.exists() || !file.open(QIODevice::ReadOnly))
        return false;

    const QByteArray fileData = file.readAll();
    file.close();

    QJsonDocument document = QJsonDocument::fromJson(fileData);
    if (!document.isObject())
        return false;

    QJsonObject root = document.object();
    const bool wasEncrypted = root.value("encrypted").toBool(false);
    if (wasEncrypted)
    {
        QByteArray plainText;
        if (!decryptStatePayload(m_username, root, &plainText))
            return false;

        document = QJsonDocument::fromJson(plainText);
        if (!document.isObject())
            return false;
        root = document.object();
    }

    m_store->identityPublic = fromBase64(root, "identityPublic");
    m_store->identityPrivate = fromBase64(root, "identityPrivate");
    m_store->registrationId = static_cast<quint32>(root.value("registrationId").toInt());
    m_store->sessions = jsonToByteMap(root.value("sessions").toObject());
    m_store->preKeys = jsonToKeyMap(root.value("preKeys").toObject());
    m_store->signedPreKeys = jsonToKeyMap(root.value("signedPreKeys").toObject());
    m_store->identities = jsonToByteMap(root.value("identities").toObject());
    m_localBundle = root.value("localBundle").toObject();

    const bool valid = !m_store->identityPublic.isEmpty() &&
                       !m_store->identityPrivate.isEmpty() &&
                       m_store->registrationId != 0 &&
                       !m_localBundle.isEmpty();
    if (valid && !wasEncrypted)
        saveState();
    return valid;
}

bool SignalProtocolManager::saveState() const
{
    if (!m_store || m_username.isEmpty())
        return false;

    const QString path = stateFilePath();
    QDir().mkpath(QFileInfo(path).absolutePath());

    QJsonObject root;
    root.insert("version", 1);
    root.insert("user", m_username);
    root.insert("registrationId", static_cast<int>(m_store->registrationId));
    root.insert("identityPublic", toBase64(m_store->identityPublic));
    root.insert("identityPrivate", toBase64(m_store->identityPrivate));
    root.insert("sessions", byteMapToJson(m_store->sessions));
    root.insert("preKeys", keyMapToJson(m_store->preKeys));
    root.insert("signedPreKeys", keyMapToJson(m_store->signedPreKeys));
    root.insert("identities", byteMapToJson(m_store->identities));
    root.insert("localBundle", m_localBundle);

    QJsonObject encryptedRoot;
    const QByteArray plainText = QJsonDocument(root).toJson(QJsonDocument::Compact);
    if (!encryptStatePayload(m_username, plainText, &encryptedRoot))
        return false;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    file.write(QJsonDocument(encryptedRoot).toJson(QJsonDocument::Indented));
    file.close();
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

QString SignalProtocolManager::stateFilePath() const
{
    QString basePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (basePath.isEmpty())
        basePath = QDir::homePath() + "/.tcp_messenger";

    const QString safeUser = QString::fromLatin1(QUrl::toPercentEncoding(m_username));
    return QDir(basePath).filePath("signal_state_" + safeUser + ".json");
}

void SignalProtocolManager::cleanup()
{
    if (m_storeContext)
        signal_protocol_store_context_destroy(m_storeContext);
    if (m_context)
        signal_context_destroy(m_context);
    delete m_store;
    m_storeContext = nullptr;
    m_context = nullptr;
    m_store = nullptr;
    m_localBundle = {};
}
