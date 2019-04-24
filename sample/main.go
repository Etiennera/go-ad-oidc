package main

import (
	"context"
	"encoding/gob"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/boj/redistore"
	ad "github.com/etiennera/go-ad-oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var store *redistore.RediStore

const storeKey = "abc123"

func helloWorldHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, world!\n"))

	var session *sessions.Session
	var err error
	if session, err = store.Get(r, storeKey); err != nil {
		w.Write([]byte("Anonymous"))
		return
	}

	if user, err := ad.UserFromSession(session); err == nil {
		w.Write([]byte(user.Claims.Name))
		return
	}

	w.Write([]byte(err.Error()))

	return
}

func main() {
	var err error
	store, err = redistore.NewRediStore(10, "tcp", ":6379", "", []byte("secret-key"))
	if err != nil {
		panic(err)
	}
	defer store.Close()

	gob.Register(ad.User{})

	client := ad.NewClient(
		"tenant id",
		"client id",
		"client secret",
		"http://localhost:8080/signin",
		store,
		storeKey,
	)

	r := mux.NewRouter()

	sessionPage := mux.NewRouter()
	sessionPage.Use(client.AuthMiddleware())
	sessionPage.HandleFunc("/session", client.SessionDetailsPage())

	r.Handle("/session", sessionPage)
	r.HandleFunc("/signin", client.DefaultSignInHandler)
	r.HandleFunc("/signout", client.DefaultSignOutHandler)
	r.HandleFunc("/", helloWorldHandler)

	http.Handle("/", r)

	srv := &http.Server{
		Addr:         "0.0.0.0:8080",
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("shutting down")
	defer os.Exit(0)
	runtime.Goexit()
}
