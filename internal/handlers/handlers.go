package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"microsoft-firebase-custom-idp/config"
	"microsoft-firebase-custom-idp/models"
	"microsoft-firebase-custom-idp/services"
	"net/http"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
	"google.golang.org/api/option"
)

const (
	// Firebase URLs
	_urlSendOobCode           = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key="
	_urlSignInWithPassword    = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
	_urlSignInWithCustomToken = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key="

	_returnSecureToken = "true"
)

var oauth2Config = &oauth2.Config{
	ClientID:     config.GetConfig().Azure.AzureClientID,
	ClientSecret: config.GetConfig().Azure.AzureClientSecret,
	RedirectURL:  config.GetConfig().Azure.AzureCallbackURL,
	Scopes:       []string{"https://graph.microsoft.com/.default"},
	Endpoint:     microsoft.AzureADEndpoint(config.GetConfig().Azure.AzureTenantID),
}

// Initialize Firebase
func initFirebaseAuth(ctx context.Context) *auth.Client {
	var firebaseConfig = config.GetConfig().Firebase

	firebaseConfig.PrivateKey = strings.ReplaceAll(firebaseConfig.PrivateKey, "\\n", "\n")

	jsonConfig, err := json.Marshal(firebaseConfig)
	if err != nil {
		log.Fatalf("Failed to marshal firebase config: %v", err)
	}

	opt := option.WithCredentialsJSON(jsonConfig)

	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		log.Fatalf("error initializing Firebase app: %v", err)
	}

	auth, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("failed to get firebase auth client: %v", err)
	}

	return auth
}

func HandleMain(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("internal/templates/index.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL("state-token", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandlePasswordResetEmail(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	var data = map[string]string{
		"requestType": "PASSWORD_RESET",
		"email":       email,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	url := _urlSendOobCode + config.GetConfig().Firebase.FirebaseApiKey
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// You can handle the response here according to your requirement
	w.Write([]byte("Password reset email sent"))
}

func HandleSignUpWithEmailPassword(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	authClient := initFirebaseAuth(ctx)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")

	user, err := authClient.GetUserByEmail(ctx, email)
	if err == nil {
		// Check if user has a password set (Firebase Admin SDK does not expose password directly, so use the sign-in method list)
		hasPassword := false
		for _, provider := range user.ProviderUserInfo {
			if provider.ProviderID == "password" {
				hasPassword = true
				break
			}
		}

		if !hasPassword {
			http.Error(w, "No password set for this user, please use reset password or use a different sign-in method.", http.StatusUnauthorized)
			return
		}
	}

	// Create a new user
	userParams := (&auth.UserToCreate{}).
		Email(email).
		Password(password)
	userRecord, err := authClient.CreateUser(ctx, userParams)
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Use GORM to save the user in the SQLite database
	newUser := models.User{
		Email:       email,
		FirebaseUID: userRecord.UID,
	}

	result := services.DB.Create(&newUser)
	if result.Error != nil {
		http.Error(w, "Failed to save user in database: "+result.Error.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "User %s created successfully", userRecord.Email)
}

func HandleEmailPasswordLogin(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	authClient := initFirebaseAuth(ctx)

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Check if user exists
	user, err := authClient.GetUserByEmail(ctx, email)
	if err != nil {
		http.Error(w, "User does not exist or other error: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Check if user has a password set (Firebase Admin SDK does not expose password directly, so use the sign-in method list)
	hasPassword := false
	for _, provider := range user.ProviderUserInfo {
		if provider.ProviderID == "password" {
			hasPassword = true
			break
		}
	}

	if !hasPassword {
		http.Error(w, "No password set for this user, please use reset password or use a different sign-in method.", http.StatusUnauthorized)
		return
	}

	// If user exists and has a password, attempt login using Firebase REST API
	url := _urlSignInWithPassword + config.GetConfig().Firebase.FirebaseApiKey
	requestBody, _ := json.Marshal(map[string]string{
		"email":             email,
		"password":          password,
		"returnSecureToken": _returnSecureToken,
	})

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		http.Error(w, "Failed during request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		http.Error(w, "Error unmarshaling response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := result["error"]; ok {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", result["error"]), http.StatusUnauthorized)
		return
	}

	// Fetch user details from database
	var dbUser models.User
	dbResult := services.DB.Where("email = ?", email).First(&dbUser)
	if dbResult.Error != nil {
		http.Error(w, "Database fetch failed: "+dbResult.Error.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Authentication Successful</h1>")
	fmt.Fprintf(w, "<p>User ID: %s</p>", dbUser.ID)
	fmt.Fprintf(w, "<p>Firebase UID: %s</p>", dbUser.FirebaseUID)
	fmt.Fprintf(w, "<p>Email: %s</p>", dbUser.Email)
	fmt.Fprintf(w, "<p>ID Token: %s</p>", result["idToken"])
	fmt.Fprintf(w, "<p>Refresh Token: %s</p>", result["refreshToken"])
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	claims, err := parseToken(token.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	email, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Email claim is missing", http.StatusInternalServerError)
		return
	}

	authClient := initFirebaseAuth(ctx)

	user, err := createUserIfNotExist(ctx, authClient, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch user from database or create if not exists
	var dbUser models.User
	result := services.DB.Where("email = ?", email).First(&dbUser)
	if result.Error != nil { // User not found, creating new one
		newUser := models.User{
			Email:       email,
			FirebaseUID: user.UID,
		}

		createResult := services.DB.Create(&newUser)
		if createResult.Error != nil {
			http.Error(w, "Failed to save user in database: "+createResult.Error.Error(), http.StatusInternalServerError)
			return
		}
		dbUser = newUser
	}

	customToken, err := authClient.CustomToken(ctx, user.UID)
	if err != nil {
		http.Error(w, "Failed to create custom token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := exchangeCustomTokenForIdToken(customToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Authentication Successful</h1>")
	fmt.Fprintf(w, "<p>User ID: %s</p>", dbUser.ID)
	fmt.Fprintf(w, "<p>Firebase UID: %s</p>", dbUser.FirebaseUID)
	fmt.Fprintf(w, "<p>Email: %s</p>", dbUser.Email)
	fmt.Fprintf(w, "<p>ID Token: %s</p>", response["idToken"])
	fmt.Fprintf(w, "<p>Refresh Token: %s</p>", response["refreshToken"])
}

func exchangeCustomTokenForIdToken(customToken string) (map[string]interface{}, error) {
	url := _urlSignInWithCustomToken + config.GetConfig().Firebase.FirebaseApiKey
	values := map[string]string{"token": customToken, "returnSecureToken": _returnSecureToken}
	jsonValue, _ := json.Marshal(values)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, fmt.Errorf("failed to request ID token: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return result, nil
}

func parseToken(accessToken string) (jwt.MapClaims, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("failed to parse claims")
}

func createUserIfNotExist(ctx context.Context, client *auth.Client, email string) (*auth.UserRecord, error) {
	user, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		return client.CreateUser(ctx, (&auth.UserToCreate{}).Email(email))
	}
	return user, nil
}
