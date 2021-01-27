/*
 *    This software is in the public domain, furnished "as is", without technical
 *    support, and with no warranty, express or implied, as to its usefulness for
 *    any purpose.
 *
 */
#include "account.h"
#include "libsync/creds/credentialmanager.h"

#include "syncenginetestutils.h"

#include <QTest>

namespace OCC {

class TestCredentialManager : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testSetGet_data()
    {
        QTest::addColumn<QVariant>("data");

        QTest::newRow("bool") << QVariant::fromValue(true);
        QTest::newRow("int") << QVariant::fromValue(1);
        QTest::newRow("map") << QVariant::fromValue(QVariantMap { { "foo", QColor(Qt::red) }, { "bar", "42" } });
    }

    void testSetGet()
    {
        QFETCH(QVariant, data);

        FakeFolder fakeFolder { FileInfo::A12_B12_C12_S12() };
        auto creds = fakeFolder.account()->credentialManager();

        connect(creds, &CredentialManager::keySet, this, [this, creds, data](const QString &key) {
            auto job = creds->get(key);
            connect(job, &CredentialJob::finished, this, [job, data, creds] {
                QCOMPARE(job->data(), data);
                creds->clear();
            });
        });

        connect(creds, &CredentialManager::keyRemoved, this, [creds, data](const QString &key) {
            QVERIFY(creds->knownKeys().isEmpty());
        });
        creds->set("test", data);
    }
};
}

QTEST_GUILESS_MAIN(OCC::TestCredentialManager)
#include "testcredentialmanager.moc"
