package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("your_secret_key")

// MongoDB Client
var client *mongo.Client

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Initialize MongoDB connection
func init() {
	clientOptions := options.Client().ApplyURI("mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
	var err error
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB!")
}

// Hash password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Check password hash
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Signup Handler
func Signup(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := hashPassword(creds.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Save user to MongoDB
	collection := client.Database("test").Collection("users")
	_, err = collection.InsertOne(context.TODO(), map[string]string{
		"username": creds.Username,
		"password": hashedPassword,
	})
	if err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Signup successful"))
}

// Login Handler
func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Retrieve user from MongoDB
	collection := client.Database("test").Collection("users")
	var user Credentials
	err = collection.FindOne(context.TODO(), map[string]string{"username": creds.Username}).Decode(&user)
	if err != nil || !checkPasswordHash(creds.Password, user.Password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	w.Write([]byte("Login successful"))
}

// Protected profile route
func Profile(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	tokenStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !tkn.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func main() {
	http.HandleFunc("/signup", Signup)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/profile", Profile)

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
