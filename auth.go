package goadoidc

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

// userSessionKey is a key unique to this project such that storage into the session does not conflict with other packages
var userSessionKey = "github.com/etiennera/go-ad-oidc user"

// OverrideUserSessionKey allow the session key to be changed for edge cases importing the package multiple times
func OverrideUserSessionKey(override string) {
	userSessionKey = override
}

// User holds claims for a user and the refresh token provided by the authority for making Microsoft API calls
type User struct {
	Claims       *Claims
	RefreshToken string
}

// SaveToSession saves to a session in values the user under the userSessionKey
func (user *User) SaveToSession(sess *sessions.Session) error {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(user); err != nil {
		return err
	}
	sess.Values[userSessionKey] = buffer.Bytes()
	return nil
}

// UserFromSession returns a user from a session if it exists
func UserFromSession(sess *sessions.Session) (*User, error) {
	buffer := bytes.Buffer{}
	var b interface{}
	var ok bool
	if b, ok = sess.Values[userSessionKey]; !ok {
		return nil, errors.New("no session")
	}
	if _, err := buffer.Write(b.([]byte)); err != nil {
		return nil, err
	}
	decoder := gob.NewDecoder(&buffer)
	user := &User{}
	if err := decoder.Decode(user); err != nil {
		return nil, err
	}
	if user.Claims.VerifyExpiresAt(time.Now().Unix(), false) {
		return user, nil
	}
	return nil, errors.New("expired")
}

// AuthMiddleware redirects to the authority with instruction to redirect to the redirect URL provided to client on its instantiation if the user is not signed in.
// AuthMiddleware can be wrapped in a method with skip conditions to bypass it, or encapsulated to match the signature for various framework middlewares.
func (client *Client) AuthMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := client.store.Get(r, client.storeKey)
			if err != nil {
				log.Println(err.Error())
			}

			user, err := UserFromSession(session)
			if err != nil {
				fmt.Println(err)
			}

			if user != nil {
				next.ServeHTTP(w, r)
			} else {
				nonce := "abc"
				session.AddFlash(r.URL.String(), "redirect_to")
				session.AddFlash(nonce, "nonce")
				session.Save(r, w)
				client.DoRedirect(w, nonce)
			}
		})
	}
}

// SessionDetailsPage will show the claims and groups attributed to a given session if one exists
func (client *Client) SessionDetailsPage() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := client.store.Get(r, client.storeKey)
		if err != nil {
			log.Println(err.Error())
		}

		user, err := UserFromSession(session)
		if err != nil {
			fmt.Println(err)
		}

		groups, err := client.getGroups(user.RefreshToken)
		w.Write([]byte(fmt.Sprintf("%+v", groups)))
		w.Write([]byte(fmt.Sprintf("%+v", user)))
		return
	}
}

// DefaultSignInHandler returns a javascript redirect to a URL determined in the session flash value "redirect_to"
func (client *Client) DefaultSignInHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		response, err := client.SignInFunc(r)
		if err != nil {
			http.Error(w, "Unknown Error", http.StatusInternalServerError)
			return
		}

		var session *sessions.Session
		if session, err = client.store.Get(r, client.storeKey); err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if nonce := session.Flashes("nonce"); len(nonce) == 0 || nonce[0] != response.Claims.Nonce {
			http.Error(w, "Forbidden", http.StatusForbidden)
			session.Save(r, w)
			return
		}

		user := &User{
			Claims:       response.Claims,
			RefreshToken: response.RefreshToken,
		}

		user.SaveToSession(session)

		if f := session.Flashes("redirect_to"); len(f) > 0 {
			session.Save(r, w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(
				`<!DOCTYPE HTML5>
					<html>
						<head>
							<title>redirecting...</title>
						</head>
					<body>
						<script>
							window.location.href = "` + f[0].(string) + `";
						</script>
					</body>
					</html>`,
			))
		}
	}
}

// SignOut deletes from the store the session for the executing request.
// If the session should only partially be deleted, the key to access the value for the user can be known by defining it in the importing package and overriding the default on initialization,
// then operating on the store from the importing package.
func (client *Client) SignOut(w http.ResponseWriter, r *http.Request) {
	var session *sessions.Session
	var err error
	if session, err = client.store.Get(r, client.storeKey); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	session.Options.MaxAge = -1
	session.Save(r, w)
}

// DefaultSignOutHandler calls SignOut and writes "signed out" to the response body.
func (client *Client) DefaultSignOutHandler(w http.ResponseWriter, r *http.Request) {
	client.SignOut(w, r)

	w.Write([]byte("signed out"))
}
