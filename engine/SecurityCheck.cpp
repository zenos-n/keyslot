// SPDX-License-Identifier: GPL-3.0-only
// Build-time checks only; this executable is never installed with the application.
#include "config-keepassx.h"
#include "KeyslotBrowserValues.h"
#include "browser/BrowserMessageBuilder.h"
#include "browser/BrowserShared.h"
#include "core/Entry.h"
#include "crypto/Crypto.h"
#include "crypto/CryptoHash.h"
#include "crypto/SymmetricCipher.h"
#include "crypto/kdf/AesKdf.h"
#include "core/Database.h"
#include "core/Group.h"
#include "format/KeePass1Reader.h"
#include "format/KdbxXmlReader.h"
#include "format/KeePass2.h"
#include "keys/PasswordKey.h"
#include "streams/SymmetricCipherStream.h"
#include <QBuffer>
#include <QCoreApplication>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

namespace {
void* watched = nullptr;
std::size_t watchedSize = 0;
bool sawScrubbedFree = false;
int checks = 0;
void require(bool valid, const char* message) {
    ++checks;
    if (!valid) { std::fprintf(stderr, "Security check failed: %s\n", message); std::exit(1); }
}
QString encoded(int count) { return QString::fromLatin1(QByteArray(count, 'x').toBase64()); }
QByteArray u32(quint32 value) {
    QByteArray bytes;
    for (int i = 0; i < 4; ++i) bytes.append(char(value >> (i * 8)));
    return bytes;
}
QByteArray field(quint16 type, const QByteArray& value) {
    QByteArray bytes;
    bytes.append(char(type)); bytes.append(char(type >> 8));
    return bytes + u32(value.size()) + value;
}
QByteArray record(const QByteArray& uuid, const QByteArray& notes, const QByteArray& data, bool alias = false) {
    auto bytes = field(1, uuid) + field(2, u32(1)) + field(3, u32(0));
    if (alias) bytes += field(1, QByteArray(16, 'z'));
    if (notes.isEmpty()) return bytes + field(4, QByteArray("Public entry\0", 13))
        + field(6, QByteArray("alice\0", 6)) + field(7, QByteArray("public password\0", 16)) + field(0xffff, {});
    return bytes + field(4, QByteArray("Meta-Info\0", 10)) + field(5, QByteArray("$\0", 2))
        + field(6, QByteArray("SYSTEM\0", 7)) + field(8, notes + '\0')
        + field(13, QByteArray("bin-stream\0", 11)) + field(14, data) + field(0xffff, {});
}
QSharedPointer<Database> legacy(const QList<QByteArray>& records) {
    const auto seed = QByteArray(16, 's'), iv = QByteArray(16, 'i'), transformSeed = QByteArray(32, 't');
    auto payload = field(1, u32(1)) + field(2, QByteArray("Fixture\0", 8))
        + field(8, QByteArray(2, '\0')) + field(0xffff, {});
    for (const auto& entry : records) payload += entry;
    const auto digest = CryptoHash::hash(payload, CryptoHash::Sha256);
    AesKdf kdf(true); kdf.setSeed(transformSeed); kdf.setRounds(1);
    QByteArray transformed;
    require(kdf.transform(CryptoHash::hash("public fixture master", CryptoHash::Sha256), transformed), "legacy fixture KDF");
    SymmetricCipher cipher;
    require(cipher.init(SymmetricCipher::Aes256_CBC, SymmetricCipher::Encrypt,
                        CryptoHash::hash(seed + transformed, CryptoHash::Sha256), iv), "legacy fixture cipher");
    require(cipher.finish(payload), "legacy fixture encrypted");
    QByteArray file = u32(0x9aa2d903) + u32(0xb54bfb65) + u32(2) + u32(0x30002) + seed + iv
        + u32(1) + u32(records.size()) + digest + transformSeed + u32(1) + payload;
    QBuffer buffer(&file); buffer.open(QIODevice::ReadOnly);
    KeePass1Reader reader;
    auto database = reader.readDatabase(&buffer, "public fixture master", static_cast<QIODevice*>(nullptr));
    require(database && !reader.hasError(), "legacy import survives metadata regression");
    const auto entries = database->rootGroup()->entriesRecursive();
    require(entries.size() == 1 && entries.first()->title() == "Public entry"
            && entries.first()->password() == "public password", "legacy import preserves ordinary credential");
    return database;
}
void serializationChecks() {
    for (const auto mode : {SymmetricCipher::ChaCha20, SymmetricCipher::Salsa20, SymmetricCipher::Aes256_CTR,
                            SymmetricCipher::Aes256_CBC, SymmetricCipher::Twofish_CBC}) {
        for (const int size : {0, 1, 1023, 1024, 1025, 2048}) {
            const int ivSize = mode == SymmetricCipher::Salsa20 ? 8 : SymmetricCipher::defaultIvSize(mode);
            const QByteArray key(SymmetricCipher::keySize(mode), 'k'), iv(ivSize, 'i');
            const QByteArray plaintext(size, 'x');
            QBuffer output; output.open(QIODevice::WriteOnly);
            SymmetricCipherStream writer(&output);
            require(writer.init(mode, SymmetricCipher::Encrypt, key, iv), "stream cipher initialized");
            require(writer.open(QIODevice::WriteOnly), "stream cipher opened");
            require(writer.write(plaintext) == size, "stream cipher write");
            require(writer.reset(), "empty and exact-boundary finalization");
            QBuffer input; input.setData(output.data()); input.open(QIODevice::ReadOnly);
            SymmetricCipherStream reader(&input);
            require(reader.init(mode, SymmetricCipher::Decrypt, key, iv), "stream decipher initialized");
            require(reader.open(QIODevice::ReadOnly), "stream decipher opened");
            require(reader.readAll() == plaintext, "stream cipher exact round trip");
        }
    }
    Database database;
    database.setFormatVersion(KeePass2::FILE_VERSION_4);
    database.setKdf(KeePass2::uuidToKdf(KeePass2::KDF_ARGON2ID));
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create("public XML fixture master"));
    require(database.setKey(key), "XML fixture key");
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid()); entry->setGroup(database.rootGroup()); entry->setTitle("Public XML fixture");
    const QByteArray oldBytes("public old attachment\0\xff", 23), newBytes("public new attachment\0\xfe", 23);
    entry->attachments()->set("Fixture.bin", oldBytes);
    entry->beginUpdate(); entry->attachments()->set("Fixture.bin", newBytes); entry->endUpdate();
    QByteArray xml;
    require(database.extract(xml), "KDBX4 XML export");
    QBuffer input(&xml); input.open(QIODevice::ReadOnly);
    KdbxXmlReader reader(KeePass2::FILE_VERSION_4);
    const auto imported = reader.readDatabase(&input);
    require(imported && !reader.hasError(), "KDBX4 XML reimport");
    auto* restored = imported->rootGroup()->findEntryByUuid(entry->uuid());
    require(restored && restored->attachments()->value("Fixture.bin") == newBytes, "current attachment retained by XML");
    require(restored->historyItems().size() == 1
            && restored->historyItems().first()->attachments()->value("Fixture.bin") == oldBytes,
            "historical attachment retained by XML");
}
void legacyChecks() {
    const auto normal = record(QByteArray(16, 'a'), {}, {});
    legacy({normal});
    // The first metadata entry is deleted before the later custom-icon table names its UUID.
    const auto image = QByteArray::fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aF1EAAAAASUVORK5CYII=");
    for (const bool alias : {false, true}) {
        const auto target = QByteArray(16, alias ? 'z' : 'm');
        const auto icons = u32(1) + u32(1) + u32(0) + u32(image.size()) + image + target + u32(0);
        legacy({normal, record(QByteArray(16, 'm'), "Unknown fixture metadata", "x", alias),
                record(QByteArray(16, 'n'), "KPX_CUSTOM_ICONS_4", icons)});
    }
    // 0xcccccccd * 5 wraps to one in 32 bits; it must never enter the group-reading loop.
    legacy({normal, record(QByteArray(16, 'm'), "KPX_GROUP_TREE_STATE", u32(0xcccccccd) + 'x')});
    for (const auto& icons : {u32(1) + u32(0) + u32(0) + u32(0xfffffff0),
                              u32(0) + u32(0x40000000) + u32(0),
                              u32(0) + u32(0) + u32(0x20000000)})
        legacy({normal, record(QByteArray(16, 'm'), "KPX_CUSTOM_ICONS_4", icons)});
}

}
extern "C" void __real_free(void*);
extern "C" void __wrap_free(void* address) {
    if (address == watched && watched) {
        auto bytes = static_cast<const unsigned char*>(address);
        sawScrubbedFree = true;
        for (std::size_t i = 0; i < watchedSize; ++i) if (bytes[i] != 0) sawScrubbedFree = false;
        watched = nullptr;
    }
    __real_free(address);
}

int main(int argc, char** argv) {
    QCoreApplication application(argc, argv);
    require(Crypto::init(), "crypto initialization");
    legacyChecks();
    serializationChecks();
    auto* codec = browserMessageBuilder();
    const auto sender = codec->getKeyPair(), recipient = codec->getKeyPair();
    const auto nonce = encoded(24);
    const int limit = BrowserShared::NATIVEMSG_MAX_LENGTH;
    for (const int size : {1, 15, 16, 1024, limit - 16, limit - 1, limit}) {
        const QString text(size, 'x');
        const auto encrypted = codec->encrypt(text, nonce, recipient.first, sender.second);
        require(!encrypted.isEmpty(), "bounded encryption");
        require(QByteArray::fromBase64(encrypted.toLatin1()).size() == size + 16, "exact ciphertext capacity");
        require(encrypted.size() <= BrowserShared::SOCKET_BUFFER_SIZE, "wire bound");
        require(codec->decrypt(encrypted, nonce, sender.first, recipient.second) == text.toUtf8(), "bounded decryption");
    }
    require(codec->encrypt(QString(limit + 1, 'x'), nonce, recipient.first, sender.second).isEmpty(), "oversized encryption rejected");
    const auto embedded = QString::fromUtf8("a\0b", 3);
    const auto encrypted = codec->encrypt(embedded, nonce, recipient.first, sender.second);
    require(codec->decrypt(encrypted, nonce, sender.first, recipient.second) == QByteArray("a\0b", 3), "embedded zero is not truncated");
    const auto unicode = QString::fromUtf8("\xe2\x98\x83").repeated(limit / 3);
    require(!codec->encrypt(unicode, nonce, recipient.first, sender.second).isEmpty(), "UTF8 byte limit accepts boundary");
    require(codec->encrypt(unicode + QString::fromUtf8("\xe2\x98\x83"), nonce, recipient.first, sender.second).isEmpty(), "UTF8 bytes bounded independently of UTF16 length");
    for (const int size : {0, 1, 23, 25}) {
        require(codec->encrypt("value", encoded(size), recipient.first, sender.second).isEmpty(), "nonce length checked for encrypt");
        require(codec->decrypt(encrypted, encoded(size), sender.first, recipient.second).isEmpty(), "nonce length checked for decrypt");
        require(codec->incrementNonce(encoded(size)).isEmpty(), "nonce increment length checked");
    }
    for (const int size : {0, 1, 31, 33}) {
        require(codec->encrypt("value", nonce, encoded(size), sender.second).isEmpty(), "public key length checked");
        require(codec->encrypt("value", nonce, recipient.first, encoded(size)).isEmpty(), "secret key length checked");
        require(codec->decrypt(encrypted, nonce, encoded(size), recipient.second).isEmpty(), "decrypt public key length checked");
        require(codec->decrypt(encrypted, nonce, sender.first, encoded(size)).isEmpty(), "decrypt secret key length checked");
    }
    for (const int size : {0, 1, 15, 16}) require(codec->decrypt(encoded(size), nonce, sender.first, recipient.second).isEmpty(), "short ciphertext rejected");
    require(codec->decrypt(encoded(limit + 17), nonce, sender.first, recipient.second).isEmpty(), "oversized ciphertext rejected");
    require(codec->base64Decode("!!!!").isEmpty(), "invalid base64 rejected");
    for (const auto& text : {QString("{REF:P@T:Private}"), QString("prefix {ref:p@t:Private} suffix"),
                            QString("\\{PASSWORD\\}"), QString("{T-CONV:/{USERNAME}/BASE64/}"),
                            QString("{S:Private}"), QString("{DB_DIR}"), QString("{{{{{USERNAME}}}}}")})
        require(keyslotBrowserHasPlaceholder(text), "known placeholder rejected");
    require(keyslotBrowserHasPlaceholder(QString(64, '{') + "{REF:P@T:Private}" + QString(64, '}')), "deep reference rejected");
    for (const auto& text : {QString("ordinary-password"), QString("literal {unknown} braces"), QString("}"), QString("{a:b}")})
        require(!keyslotBrowserHasPlaceholder(text), "literal non-placeholder remains valid");
    Entry entry;
    entry.setUuid(QUuid::createUuid());
    entry.setTitle("before");
    entry.customData()->set("Fixture", "public metadata");
    entry.beginUpdate(); entry.setTitle("after"); entry.endUpdate();
    require(entry.historyItems().size() == 1, "history created");
    require(entry.historyItems().first()->customData()->value("Fixture") == "public metadata", "history retains custom metadata");
    watchedSize = 97;
    watched = ::operator new(watchedSize);
    auto* data = static_cast<volatile unsigned char*>(watched);
    for (std::size_t i = 0; i < watchedSize; ++i) data[i] = 0x5a;
    ::operator delete(watched);
    require(sawScrubbedFree, "unsized C++ delete scrubs before free");
    std::printf("Native security checks: %d PASS\n", checks);
    return 0;
}
