package main

import (
	"context"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"io"
	"net/http/httputil"
	"net/url"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-redis/redis/v8"
	"encoding/json"
	"github.com/golang-jwt/jwt"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-session/session"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
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

	manager.MapAccessGenerate(generates.NewJWTAccessGenerate(
		"", []byte(os.Getenv("SECRET_KEY")), jwt.SigningMethodHS512,
	))

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

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)

	//srv.SetAllowGetAccessRequest(true)
	//srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DUMPVAR") == "1" {
			dumpRequest(os.Stdout, "authorize", r)
		}

		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DUMPVAR") == "1" {
			_ = dumpRequest(os.Stdout, "token", r)
		}
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DUMPVAR") == "1" {
			_ = dumpRequest(os.Stdout, "userinfo", r)
		}
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	log.Println("Server is running at 9096 port.")
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://127.0.0.1", 9096, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://127.0.0.1", 9096, "/oauth/token")
	log.Fatal(http.ListenAndServe(":9096", nil))
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if os.Getenv("DUMPVAR") == "1" {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r)
	}
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("DUMPVAR") == "1" {
		_ = dumpRequest(os.Stdout, "login", r)
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		store.Set("LoggedInUserID", r.Form.Get("username"))
		store.Save()

		w.Header().Set("Location", "/auth")
		w.WriteHeader(http.StatusFound)
		return
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("DUMPVAR") == "1" {
		_ = dumpRequest(os.Stdout, "auth", r)
	}
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}
