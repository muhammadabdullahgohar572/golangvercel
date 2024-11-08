// main.go

package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	. "github.com/tbxark/g4vercel"
)

// Global variable to hold the database connection
var database *gorm.DB

type CreateUserData struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Gender   string `json:"gender"`
	Company  string `json:"company"`
	jwt.StandardClaims
}


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

	// Automatically migrate the schema
	database.AutoMigrate(&CreateUserData{})
}

// Handler function for handling requests
func Handler(w http.ResponseWriter, r *http.Request) {
	server := New()
	Dbconnect() // Initialize the database connection

	server.GET("/", func(context *Context) {
		context.JSON(200, H{
			"message": "hello go from vercel ",
		})
	})
	server.GET("/hello", func(context *Context) {
		name := context.Query("name")
		if name == "" {
			context.JSON(400, H{
				"message": "name not found",
			})
		} else {
			context.JSON(200, H{
				"data": fmt.Sprintf("Hello %s!", name),
			})
		}
	})
	server.GET("/user/:id", func(context *Context) {
		context.JSON(400, H{
			"data": H{
				"id": context.Param("id"),
			},
		})
	})
	server.GET("/long/long/long/path/*test", func(context *Context) {
		context.JSON(200, H{
			"data": H{
				"url": context.Path,
			},
		})
	})

	server.Handle(w, r)
}
