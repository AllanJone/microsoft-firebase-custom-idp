package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// Config struct
type Config struct {
	Firebase *Firebase
	Azure    *Azure
}

// Firebase struct
type Firebase struct {
	Type                        string `json:"type"                        envconfig:"FIREBASE_TYPE"                        required:"true"`
	ProjectID                   string `json:"project_id"                  envconfig:"FIREBASE_PROJECT_ID"                  required:"true"`
	PrivateKeyID                string `json:"private_key_id"               envconfig:"FIREBASE_PRIVATE_KEY_ID"              required:"true"`
	PrivateKey                  string `json:"private_key"                  envconfig:"FIREBASE_PRIVATE_KEY"                 required:"true"`
	ClientEmail                 string `json:"client_email"                 envconfig:"FIREBASE_CLIENT_EMAIL"                required:"true"`
	ClientID                    string `json:"client_id"                    envconfig:"FIREBASE_CLIENT_ID"                   required:"true"`
	AuthURI                     string `json:"auth_uri"                     envconfig:"FIREBASE_AUTH_URI"                    required:"true"`
	TokenURI                    string `json:"token_uri"                    envconfig:"FIREBASE_TOKEN_URI"                   required:"true"`
	AuthProviderX509CertURL     string `json:"auth_provider_x509_cert_url"   envconfig:"FIREBASE_AUTH_PROVIDER_X509_CERT_URL" required:"true"`
	ClientX509CertURL           string `json:"client_x509_cert_url"          envconfig:"FIREBASE_CLIENT_X509_CERT_URL"        required:"true"`
	UniverseDomain              string `json:"universe_domain"               envconfig:"FIREBASE_UNIVERSE_DOMAIN"             required:"true"`
	FirebaseBase64SignerKey     string `                                envconfig:"FIREBASE_BASE64_SIGNER_KEY"           required:"true"`
	FirebaseBase64SaltSeparator string `                                envconfig:"FIREBASE_BASE64_SALT_SEPARATOR"       required:"true"`
	FirebaseApiKey              string `                                envconfig:"FIREBASE_API_KEY"       required:"true"`
}

// Firebase struct
type Azure struct {
	AzureClientID     string `envconfig:"AZURE_CLIENT_ID"                        required:"true"`
	AzureClientSecret string `envconfig:"AZURE_CLIENT_SECRET"                  required:"true"`
	AzureTenantID     string `envconfig:"AZURE_TENANT_ID"              required:"true"`
	AzureCallbackURL  string `envconfig:"AZURE_CALLBACK_URL"                 required:"true"`
}

var _config = Config{}

// Init loads environment variables from ./.env
func init() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to get file path")
	}
	dotEnvPath := filepath.Join(file, "../../.env")
	// Check dot env file status
	if _, err := os.Stat(dotEnvPath); err != nil {
		panic(fmt.Errorf("os.Stat: %w", err))
	}
	// Load dot env file into shell
	if err := godotenv.Load(dotEnvPath); err != nil {
		panic(fmt.Errorf("godotenv.Load: %w", err))
	}
	// Load environment variables into config struct
	if err := envconfig.Process("", &_config); err != nil {
		panic(fmt.Errorf("envconfig.Process: %w", err))
	}
}

// GetConfig retrieves the configuration struct
func GetConfig() Config {
	return _config
}
