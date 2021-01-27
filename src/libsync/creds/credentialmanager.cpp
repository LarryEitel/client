#include "credentialmanager.h"

#include "account.h"
#include "theme.h"

#include "common/asserts.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QSettings>

using namespace OCC;

Q_LOGGING_CATEGORY(lcCredentaislManager, "sync.credentials.manager", QtDebugMsg)

namespace {
QString credentialKeyC()
{
    return QStringLiteral("%1_credentials").arg(Theme::instance()->appName());
}

QString accoutnKey(const Account *acc)
{
    OC_ASSERT(!acc->url().isEmpty());
    return QStringLiteral("%1:%2:%3").arg(credentialKeyC(), acc->url().host(), acc->uuid().toString(QUuid::WithoutBraces));
}


QString scope(const CredentialManager *const manager)
{
    return manager->account() ? accoutnKey(manager->account()) : credentialKeyC();
}

QString scopedKey(const CredentialManager *const manager, const QString &key)
{
    return scope(manager) + QLatin1Char(':') + key;
}
}

CredentialManager::CredentialManager(Account *acc)
    : QObject(acc)
    , _account(acc)
{
}

CredentialManager::CredentialManager(QObject *parent)
    : QObject(parent)
{
}


CredentialJob *CredentialManager::get(const QString &key)
{
    qCInfo(lcCredentaislManager) << "get" << scopedKey(this, key);
    auto out = new CredentialJob(this, key);
    connect(out, &CredentialJob::finished, this, [out, key, this] {
        if (out->error() != QKeychain::NoError) {
            Q_EMIT error(key, out->error(), out->errorString());
        }
    });
    return out;
}

void CredentialManager::set(const QString &key, const QVariant &data)
{
    qCInfo(lcCredentaislManager) << "set" << scopedKey(this, key);
    auto writeJob = new QKeychain::WritePasswordJob(Theme::instance()->appName());
    writeJob->setKey(scopedKey(this, key));
    connect(writeJob, &QKeychain::WritePasswordJob::finished, this, [writeJob, key, this] {
        if (writeJob->error() != QKeychain::NoError) {
            Q_EMIT error(key, writeJob->error(), writeJob->errorString());
        } else {
            qCInfo(lcCredentaislManager) << "added" << scopedKey(this, key);
            QSettings settings(scope(this));
            settings.setValue(key, true);
            Q_EMIT keySet(key);
        }
    });
    QJsonObject obj;
    if (data.canConvert(QVariant::Map)) {
        obj = QJsonObject::fromVariantMap(data.toMap());
    } else {
        obj.insert(QStringLiteral("d"), QJsonValue::fromVariant(data));
    }
    //    qCDebug(lcCredentaislManager) << "wrote" << QJsonDocument(obj).toJson();
    writeJob->setBinaryData(QJsonDocument(obj).toBinaryData());
    writeJob->start();
}

void CredentialManager::remove(const QString &key)
{
    OC_ASSERT(contains(key));
    qCInfo(lcCredentaislManager) << "del" << scopedKey(this, key);
    auto keychainJob = new QKeychain::DeletePasswordJob(Theme::instance()->appName());
    keychainJob->setKey(scopedKey(this, key));
    connect(keychainJob, &QKeychain::DeletePasswordJob::finished, this, [keychainJob, key, this] {
        OC_ASSERT(keychainJob->error() != QKeychain::EntryNotFound);
        if (keychainJob->error() != QKeychain::NoError) {
            Q_EMIT error(key, keychainJob->error(), keychainJob->errorString());
        } else {
            qCInfo(lcCredentaislManager) << "removed" << scopedKey(this, key);
            QSettings settings(scope(this));
            settings.remove(key);
            Q_EMIT keyRemoved(key);
        }
    });
    keychainJob->start();
}

void CredentialManager::clear()
{
    OC_ENFORCE(_account);
    const auto keys = knownKeys();
    for (const auto &key : keys) {
        remove(key);
    }
}

const Account *CredentialManager::account() const
{
    return _account;
}

bool CredentialManager::contains(const QString &key) const
{
    QSettings settings(scope(this));
    return settings.contains(key);
}

CredentialJob::CredentialJob(CredentialManager *parent, const QString &key)
    : QObject(parent)
    , _key(key)
    , _parent(parent)
{
    connect(this, &CredentialJob::finished, this, &CredentialJob::deleteLater);
}

QString CredentialJob::errorString() const
{
    return _errorString;
}

const QVariant &CredentialJob::data() const
{
    return _data;
}

QKeychain::Error CredentialJob::error() const
{
    return _error;
}

void CredentialJob::start()
{
    if (!_parent->contains(_key)) {
        _error = QKeychain::EntryNotFound;
        Q_EMIT finished();
        return;
    }

    auto keychainJob = new QKeychain::ReadPasswordJob(Theme::instance()->appName());
    keychainJob->setKey(scopedKey(_parent, _key));
    connect(keychainJob, &QKeychain::ReadPasswordJob::finished, this, [this, keychainJob] {
        OC_ASSERT(keychainJob->error() != QKeychain::EntryNotFound);
        if (keychainJob->error() == QKeychain::NoError) {
            const auto doc = QJsonDocument::fromBinaryData(keychainJob->binaryData());
            if (doc.isNull()) {
                _error = QKeychain::OtherError;
                _errorString = tr("Failed to parse credentials");
                return;
            }
            const auto obj = doc.object();
            //            qCDebug(lcCredentaislManager) << "read" << keychainJob->key() << QJsonDocument(obj).toJson();
            if (obj.count() == 1) {
                _data = obj.value(QLatin1String("d"));
            } else {
                _data = obj.toVariantMap();
            }
            OC_ASSERT(_data.isValid());
        } else {
            qCWarning(lcCredentaislManager) << "Failed to read client id" << keychainJob->errorString();
            _error = keychainJob->error();
            _errorString = keychainJob->errorString();
        }
        Q_EMIT finished();
    });
    keychainJob->start();
}

QString CredentialJob::key() const
{
    return _key;
}

QStringList CredentialManager::knownKeys() const
{
    return QSettings(scope(this)).allKeys();
}
