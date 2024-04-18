package main

import (
	"log"
	"microsoft-firebase-custom-idp/internal/handlers"
	"microsoft-firebase-custom-idp/services"
	"net/http"

	"github.com/joho/godotenv"
)

func main() {
	services.InitDatabase()

	http.HandleFunc("/", handlers.HandleMain)
	http.HandleFunc("/login", handlers.HandleLogin)
	http.HandleFunc("/login-email", handlers.HandleEmailPasswordLogin)
	http.HandleFunc("/callback", handlers.HandleCallback)
	http.HandleFunc("/signup-email", handlers.HandleSignUpWithEmailPassword)
	http.HandleFunc("/send-password-reset-email", handlers.HandlePasswordResetEmail)

	godotenv.Load()

	log.Println("Server starting on :8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
