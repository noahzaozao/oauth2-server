package main

import (
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strconv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Panic(err)
	}
}

func main() {
	// https://github.com/go-oauth2/oauth2
	manager := manage.NewDefaultManager()
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
	// use redis cluster store
	// manager.MapTokenStorage(oredis.NewRedisClusterStore(&redis.ClusterOptions{
	// 	Addrs: []string{"127.0.0.1:6379"},
	// 	DB: 15,
	// }))

	clientStore := store.NewClientStore()
	clientStore.Set(os.Getenv("OAUTH2_CLIENT_ID"), &models.Client{
		ID:     os.Getenv("OAUTH2_CLIENT_ID"),
		Secret: os.Getenv("OAUTH2_CLIENT_SECRET"),
		Domain: os.Getenv("OAUTH2_DOMAIN"),
	})
	manager.MapClientStorage(clientStore)
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate(
		"", []byte(os.Getenv("SECRET_KEY")), jwt.SigningMethodHS512,
	))

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}
