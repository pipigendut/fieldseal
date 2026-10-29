package pii_test

import (
	"bytes"
	"errors"
	"log"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/pipigendut/coinx-pii/go/pii"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const gormKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

type person struct {
	ID       uint   `gorm:"primaryKey"`
	OrangNIK string `gorm:"column:orang_nik;serializer:coinx_pii"`
}

func (person) TableName() string { return "pii_people" }

func TestGORMRoundTrip(t *testing.T) {
	if err := pii.Init(gormKeyHex); err != nil {
		t.Fatal(err)
	}
	sqlLog := &bytes.Buffer{}
	db := openPeopleDB(t, sqlLog)
	const nik = "3273010101010001"
	if err := db.Create(&person{OrangNIK: nik}).Error; err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sqlLog.Bytes(), []byte(nik)) {
		t.Fatal("sql log contains plaintext nik")
	}

	var loaded person
	if err := db.First(&loaded).Error; err != nil {
		t.Fatal(err)
	}
	if loaded.OrangNIK != nik {
		t.Fatalf("loaded %s", loaded.OrangNIK)
	}

	encrypted, err := pii.Encrypt("orang_nik", nik)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.Raw("SELECT orang_nik FROM pii_people").Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored != encrypted {
		t.Fatalf("stored %s", stored)
	}

	var found person
	err = db.Where("orang_nik = ?", nik).First(&found).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("plaintext lookup: %v", err)
	}
	if err := db.Where("orang_nik = ?", encrypted).First(&found).Error; err != nil {
		t.Fatal(err)
	}
	if found.OrangNIK != nik {
		t.Fatalf("found %s", found.OrangNIK)
	}

	dup := person{OrangNIK: nik}
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("expected unique index to reject the same nik")
	}
}

func TestGORMLegacyPlaintext(t *testing.T) {
	if err := pii.Init(gormKeyHex); err != nil {
		t.Fatal(err)
	}
	db := openPeopleDB(t, nil)
	const legacy = "3273010101010002"
	if err := db.Exec("INSERT INTO pii_people (orang_nik) VALUES (?)", legacy).Error; err != nil {
		t.Fatal(err)
	}
	var row person
	if err := db.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OrangNIK != legacy {
		t.Fatalf("legacy load %s", row.OrangNIK)
	}
	if err := db.Save(&row).Error; err != nil {
		t.Fatal(err)
	}
	encrypted, err := pii.Encrypt("orang_nik", legacy)
	if err != nil {
		t.Fatal(err)
	}
	var found person
	if err := db.Where("orang_nik = ?", encrypted).First(&found).Error; err != nil {
		t.Fatal(err)
	}
	if found.OrangNIK != legacy {
		t.Fatalf("found %s", found.OrangNIK)
	}
}

func openPeopleDB(t *testing.T, sqlLog *bytes.Buffer) *gorm.DB {
	t.Helper()
	logger := gormlogger.Discard
	if sqlLog != nil {
		logger = gormlogger.New(log.New(sqlLog, "", 0), gormlogger.Config{LogLevel: gormlogger.Info})
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&person{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX idx_pii_people_nik ON pii_people (orang_nik)").Error; err != nil {
		t.Fatal(err)
	}
	return db
}
