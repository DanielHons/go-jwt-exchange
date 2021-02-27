package main

import (
	"flag"
	"github.com/DanielHons/go-jwt-exchange/pkg/jwt_exchange"
	"gopkg.in/yaml.v3"
	_ "gopkg.in/yaml.v3"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type OutTokenConfig struct {
	JwtSecret    string            `yaml:"jwt-secret"`
	TTL          int64             `yaml:"ttl"`
	Header       string            `yaml:"header"`
	StaticClaims map[string]string `yaml:"static-claims"`
	MappedClaims map[string]string `yaml:"mapped-claims"`
}

type InTokenConfig struct {
	Header string `yaml:"header"`
}

type TokenConfig struct {
	In  InTokenConfig  `yaml:"in"`
	Out OutTokenConfig `yaml:"out"`
}

type Config struct {
	Bind     string      `yaml:"bind"`
	Token    TokenConfig `yaml:"token"`
	JwksURL  string      `yaml:"jwks-url"`
	Upstream string      `yaml:"upstream"`
}

const k_bindAddress = "BIND_ADDRESS"
const k_jwtSecret = "JWT_SECRET"
const k_jwtCreateTTL = "OUTGOING_TOKEN_TTL_SEC"
const k_jwksUrl = "JWKS_URL"
const k_tokenHeaderIn = "TOKEN_HEADER_IN"
const k_upstream = "TARGET_URL"
const k_tokenHeaderOut = "TOKEN_HEADER_OUT"

const authorization = "Authorization"
const defaultBindAddress = "0.0.0.0:9002"
const bearerPrefix = "Bearer "

const defaultTokenLifetimeSeconds = 3

var configPath string
var config *Config

func init() {
	flag.StringVar(&configPath, "c", "", "path to the config file")
	flag.Parse()
}

func main() {
	var err error
	config, err = createConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	jwksCache := jwt_exchange.StartNewJwkCache(config.JwksURL,
		24*time.Hour, true,
	)

	handler := jwt_exchange.TokenExchangeHandler{
		ClaimsExtractor: jwt_exchange.JwksClaimsExtractor{
			Validator: &jwksCache,
			TokenReader: jwt_exchange.HeaderTokenReader{
				HeaderName: config.Token.In.Header,
				TrimPrefix: true,
				Prefix:     bearerPrefix,
			},
		},
		ClaimsMapper: jwt_exchange.FancyClaimsMapper{
			TokenTTL:     readTokenLifetimeFromEnv(),
			Audience:     "",
			StaticClaims: config.Token.Out.StaticClaims,
			MappedClaims: config.Token.Out.MappedClaims,
		},
		TokenCreator: jwt_exchange.JwtCreator_HS256{
			JwtSecret: []byte(config.Token.Out.JwtSecret),
		},
		HeaderTokenWriter: jwt_exchange.HeaderTokenWriter{
			HeaderName: config.Token.Out.Header,
			Prefix:     bearerPrefix,
		},
		Director: jwt_exchange.DefaultProxyDirector(config.Upstream),
	}

	http.HandleFunc("/", handler.ProxyHandler())
	log.Fatal(http.ListenAndServe(getEnvOrDefault(k_bindAddress, defaultBindAddress), nil))
}

func getEnvOrDefault(key string, defaultValue string) string {
	env := os.Getenv(key)
	if len(env) == 0 {
		return defaultValue
	}
	return env
}

func readTokenLifetimeFromEnv() int64 {
	envLifetime := os.Getenv(k_jwtCreateTTL)
	if len(envLifetime) == 0 {
		return defaultTokenLifetimeSeconds
	}
	atoi, err := strconv.Atoi(envLifetime)
	if err != nil {
		log.Println("Could not read " + k_jwtCreateTTL + ", " +
			"using " + strconv.Itoa(defaultTokenLifetimeSeconds))
		return defaultTokenLifetimeSeconds
	}
	return int64(atoi)
}

func createConfig(configPath string) (*Config, error) {
	if configPath == "" {
		return readConfigFromEnvironment(), nil
	}
	return readConfigFromFile(configPath)
}

func readConfigFromFile(configPath string) (*Config, error) {
	// Create config structure
	config := &Config{}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func readConfigFromEnvironment() *Config {
	return &Config{
		Bind: os.Getenv(k_bindAddress),
		Token: TokenConfig{
			In: InTokenConfig{
				Header: getEnvOrDefault(k_tokenHeaderIn, authorization),
			},
			Out: OutTokenConfig{
				JwtSecret:    os.Getenv(k_jwtSecret),
				TTL:          readTokenLifetimeFromEnv(),
				Header:       getEnvOrDefault(k_tokenHeaderOut, authorization),
				StaticClaims: map[string]string{},
				MappedClaims: map[string]string{
					"sub": "sub",
				},
			},
		},
		JwksURL:  os.Getenv(k_jwksUrl),
		Upstream: os.Getenv(k_upstream),
	}
}
