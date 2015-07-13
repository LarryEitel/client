/*
 *    This software is in the public domain, furnished "as is", without technical
 *    support, and with no warranty, express or implied, as to its usefulness for
 *    any purpose.
 *
 */

#pragma once

#include <QTemporaryDir>
#include <QtTest>

#include "utility.h"
#include "folderman.h"
#include "accountstate.h"

using namespace OCC;


static FolderDefinition folderDefinition(const QString &path) {
    FolderDefinition d;
    d.localPath = path;
    d.targetPath = path;
    d.alias = path;
    return d;
}


class TestFolderMan: public QObject
{
    Q_OBJECT

    FolderMan _fm;

private slots:
    void testCheckPathValidityForNewFolder()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QDir dir2(dir.path());
        QVERIFY(dir2.mkpath("sub/ownCloud1/folder/f"));
        QVERIFY(dir2.mkpath("ownCloud2"));
        QVERIFY(dir2.mkpath("sub/free"));
        QVERIFY(dir2.mkpath("free2/sub"));

        FolderMan *folderman = FolderMan::instance();
        QCOMPARE(folderman, &_fm);
        QVERIFY(folderman->addFolder(0, folderDefinition(dir.path() + "/sub/ownCloud1")));
        QVERIFY(folderman->addFolder(0, folderDefinition(dir.path() + "/ownCloud2")));


        // those should be allowed
        QVERIFY(folderman->checkPathValidityForNewFolder(dir.path() + "/sub/free").isNull());
        QVERIFY(folderman->checkPathValidityForNewFolder(dir.path() + "/free2/").isNull());

        // Not an existing directory -> Error
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/sub/bliblablu").isNull());

        // There are folders configured in those folders: -> ERROR
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/sub/ownCloud1").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/ownCloud2/").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/sub").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/sub/").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path()).isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/sub/ownCloud1/folder").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/sub/ownCloud1/folder/f").isNull());


        // make a bunch of links
        QVERIFY(QFile::link(dir.path() + "/sub/free", dir.path() + "/link1"));
        QVERIFY(QFile::link(dir.path() + "/sub", dir.path() + "/link2"));
        QVERIFY(QFile::link(dir.path() + "/sub/ownCloud1", dir.path() + "/link3"));
        QVERIFY(QFile::link(dir.path() + "/sub/ownCloud1/folder", dir.path() + "/link4"));

        // Ok
        QVERIFY(folderman->checkPathValidityForNewFolder(dir.path() + "/link1").isNull());
        QVERIFY(folderman->checkPathValidityForNewFolder(dir.path() + "/link2/free").isNull());

        // Not Ok
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/link2").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/link3").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/link4").isNull());
        QVERIFY(!folderman->checkPathValidityForNewFolder(dir.path() + "/link3/folder").isNull());
    }
};


