package main

import (
	_ "github.com/joho/godotenv/autoload"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"os"
)

var database *gorm.DB

func Dbconnect() {
	dbUrl := os.Getenv("Dgconnect")

	if dbUrl == "" {
		log.Fatal("Database URL (Dgconnect) is not set")
	}

	var err error

	database, err = gorm.Open(mysql.Open(dbUrl), &gorm.Config{})

	if err != nil {
		log.Panicf("Failed to connect to database: %v", err)
	}

	database.AutoMigrate(&CreateUserData{})
}
