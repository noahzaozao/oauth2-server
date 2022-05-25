package main

import (
	"context"
	"github.com/go-oauth2/oauth2/v4/errors"
	//"golang.org/x/oauth2"
	//"golang.org/x/oauth2/clientcredentials"

	//"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-redis/redis/v8"
	//"github.com/golang-jwt/jwt/v4"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strconv"
	"github.com/go-session/session"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Panic(err)
	}
}

func client() {
	//config := oauth2.Config{
	//	ClientID: os.Getenv(""),
	//	ClientSecret: os.Getenv(""),
	//	Scopes: []string{"all"},
	//	RedirectURL: "",
	//	Endpoint: oauth2.Endpoint{
	//		AuthURL: "",
	//		TokenURL: "",
	//	},
	//}
	////var globalToken *oauth2.Token
	//config.AuthCodeURL()
	//config.Exchange()
	//config.TokenSource()
	//config.PasswordCredentialsToken()
	//
	//cfg := clientcredentials.Config{
	//	ClientID: "",
	//	ClientSecret: "",
	//	TokenURL: "",
	//}
	//cfg.Token()

}

func main() {
	// https://github.com/go-oauth2/oauth2
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token memory store
	//manager.MustTokenStorage(store.NewMemoryTokenStore())

	REDIS_DB, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		log.Println("error on load redis db from env:", err.Error())
		REDIS_DB = 15
	}

	// use redis token store
	manager.MapTokenStorage(oredis.NewRedisStore(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASS"),
		DB:       REDIS_DB,
	}))

	//manager.MapAccessGenerate(generates.NewJWTAccessGenerate(
	//	"", []byte(os.Getenv("SECRET_KEY")), jwt.SigningMethodHS512,
	//))

	clientStore := store.NewClientStore()
	clientStore.Set(os.Getenv("OAUTH2_CLIENT_ID"), &models.Client{
		ID:     os.Getenv("OAUTH2_CLIENT_ID"),
		Secret: os.Getenv("OAUTH2_CLIENT_SECRET"),
		Domain: os.Getenv("OAUTH2_DOMAIN"),
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
		}
		return
	})

	//srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}


func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

