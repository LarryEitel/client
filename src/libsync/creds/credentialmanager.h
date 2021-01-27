#pragma once

#include <QVariant>

#include "owncloudlib.h"

#include <qt5keychain/keychain.h>

namespace OCC {
class Account;
class CredentialJob;

class OWNCLOUDSYNC_EXPORT CredentialManager : public QObject
{
    Q_OBJECT
public:
    // global credentials
    CredentialManager(QObject *parent);
    // account related credentials
    explicit CredentialManager(Account *acc);

    CredentialJob *get(const QString &key);
    void set(const QString &key, const QVariant &data);
    void remove(const QString &key);
    /**
     * Delete all credentials asigned with an account
     */
    void clear();

    bool contains(const QString &key) const;
    const Account *account() const;

Q_SIGNALS:
    void error(const QString &key, QKeychain::Error error, const QString &errorString);

    void keySet(const QString &key);
    void keyRemoved(const QString &key);

private:
    QStringList knownKeys() const;

    const Account *const _account = nullptr;
    friend class TestCredentialManager;
};

class OWNCLOUDSYNC_EXPORT CredentialJob : public QObject
{
    Q_OBJECT
public:
    void start();
    QString key() const;

    QKeychain::Error error() const;

    const QVariant &data() const;

    QString errorString() const;

Q_SIGNALS:
    void finished();

private:
    CredentialJob(CredentialManager *parent, const QString &key);
    QString _key;
    QVariant _data;
    QKeychain::Error _error = QKeychain::NoError;
    QString _errorString;

    CredentialManager *const _parent;

    friend class CredentialManager;
};


}
