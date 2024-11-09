package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
    "github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	. "github.com/tbxark/g4vercel"
)

// Global variable to hold the database connection
var database *gorm.DB
var JWT_SECRET_KEY []byte

// Struct to hold user data
type CreateUserData struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Gender   string `json:"gender"`
	Company  string `json:"company"`
	jwt.StandardClaims
}

// Function to connect to the database
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


var jwtKey []byte

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CompareHashAndPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {

		return false // Password does not match the stored hash.

	}
	return err == nil
}

func Createuserdata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var CreateuserdataNew CreateUserData

	if err := json.NewDecoder(r.Body).Decode(&CreateuserdataNew); err != nil {
		http.Error(w, "1", http.StatusBadRequest)
		return
	}

	HashPassword, err := HashPassword(CreateuserdataNew.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	CreateuserdataNew.Password = HashPassword

	if err := database.Create(&CreateuserdataNew).Error; err != nil {
		http.Error(w, "Databasea", http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(CreateuserdataNew); err != nil {
		http.Error(w, "e", http.StatusBadRequest)
	}

}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var MatchuserData CreateUserData
	var Extinguser CreateUserData

	json.NewDecoder(r.Body).Decode(&MatchuserData)

	if err := database.Where("email = ? ", MatchuserData.Email).First(&Extinguser).Error; err != nil {
		http.Error(w, "User Email not Found", http.StatusUnauthorized)
		return
	}

	if !CompareHashAndPassword(MatchuserData.Password, Extinguser.Password) {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	TokenExpire := time.Now().Add(24 * time.Hour)
	cleams := &CreateUserData{
		Name:     Extinguser.Name,
		Email:    Extinguser.Email,
		Password: Extinguser.Password,
		Gender:   Extinguser.Gender,
		Company:  Extinguser.Company,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: TokenExpire.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cleams)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})

}

func sign(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var Extinguser CreateUserData
	var MatchuserData CreateUserData

	json.NewDecoder(r.Body).Decode(&MatchuserData)

	if err := database.Where("email = ?", MatchuserData.Email).First(&Extinguser).Error; err != nil {

		http.Error(w, "email not found", http.StatusUnauthorized)
		return
	}

	if !CompareHashAndPassword(MatchuserData.Password, Extinguser.Password) {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	TokenExpire := time.Now().Add(24 * time.Hour)

	Cleaims := &CreateUserData{
		Name:     Extinguser.Name,
		Email:    Extinguser.Email,
		Password: Extinguser.Password,
		Gender:   Extinguser.Gender,
		Company:  Extinguser.Company,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: TokenExpire.Unix(),
		},
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Cleaims)

	tokenstring, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenstring,
	})

}

func Decode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenStr := r.URL.Query().Get("token")
	if jwtKey == nil {
		jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	}
	cleims := &CreateUserData{}

	token, err := jwt.ParseWithClaims(tokenStr, cleims, func(*jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userData := map[string]interface{}{
		"UserName": cleims.Name,
		"Email":    cleims.Email,
		"Password": cleims.Password, // Include only if necessary
		"Age":      cleims.Company,
		"Gender":   cleims.Gender,
	}

	if err := json.NewEncoder(w).Encode(userData); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}



// CORS middleware to handle all origins and allow specific methods and headers
func CORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        w.Header().Set("Access-Control-Allow-Credentials", "true")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}
// Main Handler for routing
func Handler(w http.ResponseWriter, r *http.Request) {
    server := New()

    defer func() {
        if rec := recover(); rec != nil {
            fmt.Fprintf(w, "Database connection failed: %v", rec)
        }
    }()

    Dbconnect()
    jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

    // Initialize the router
    router := mux.NewRouter()
    router.Use(CORS)  // Applying CORS middleware to the router

    // Define routes with the router instance
    router.HandleFunc("/test", Createuserdata).Methods("POST", "OPTIONS")
    router.HandleFunc("/test1", sign).Methods("POST", "OPTIONS")
    router.HandleFunc("/test2", login).Methods("POST", "OPTIONS")
    router.HandleFunc("/Decode", Decode).Methods("POST", "OPTIONS")

    // Serve the router on the server
    server.GET("/", func(ctx *Context) {
        ctx.JSON(200, H{"message": "Hello from Go and Vercel"})
    })

    // Route all requests through the router
    router.ServeHTTP(w, r)
}
