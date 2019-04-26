package goadoidc

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"

	"github.com/dgrijalva/jwt-go"
	"github.com/mendsley/gojwk"
)

// Client methods allow for interacting with Microsoft APis
type Client struct {
	clientID     string
	tenantID     string
	clientSecret string
	scope        string
	baseURL      string
	redirectURI  string
	keys         []gojwk.Key
	store        sessions.Store
	storeKey     string
}

// NewClient returns a configured client associated with a given store
// A storeKey should be provided if the session is to be accessed from the importing package
func NewClient(tenantID, clientID, clientSecret, redirectURI string, store sessions.Store, storeKey ...string) *Client {
	gob.Register(Claims{})
	baseURL := fmt.Sprintf(
		rootURL+"?client_id=%s&client_secret=%s",
		tenantID,
		clientID,
		clientSecret,
	)

	client := &Client{
		clientID:     clientID,
		tenantID:     tenantID,
		clientSecret: clientSecret,
		scope:        strings.Join([]string{"?"}, "+"),
		baseURL:      baseURL,
		redirectURI:  redirectURI,
		store:        store,
		storeKey:     "GOADOIDC",
	}

	if len(storeKey) > 0 {
		if len(storeKey) > 1 {
			panic(errors.New("only one key is accepted for the variadic parameter storeKey"))
		}
		client.storeKey = storeKey[0]
	}

	return client
}

// Claims are the basic claims provided by AD
type Claims struct {
	AMR        []string `json:"amr"`
	FamilyName string   `json:"family_name"`
	GivenName  string   `json:"given_name"`
	IPAddr     string   `json:"ipaddr"`
	Name       string   `json:"name"`
	Nonce      string   `json:"nonce"`
	OID        string   `json:"oid"`
	OnPremSID  string   `json:"onprem_sid"`
	TID        string   `json:"tid"`
	UniqueName string   `json:"unique_name"`
	UPN        string   `json:"upn"`
	UTI        string   `json:"uti"`
	Ver        string   `json:"ver"`
	jwt.StandardClaims
}

// RedirectURL returns the URL used by DoRedirect to redirect to the authority
func (client *Client) RedirectURL(nonce string) string {
	return fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?"+
			"client_id=%s&response_type=id_token+code&redirect_uri=%s"+
			"&response_mode=form_post&scope=openid+profile&nonce=%s",
		client.tenantID,
		client.clientID,
		client.redirectURI,
		nonce,
	)
}

// DoRedirect returns a function that redirects to the authority
func (client *Client) DoRedirect(w http.ResponseWriter, nonce string) {
	w.Header().Add("Location", client.RedirectURL(nonce))
	w.WriteHeader(http.StatusFound)
}

// SignInResponse is returned from SignInFunc if authenticated succeeds and contains the claims and refresh token returned
type SignInResponse struct {
	Claims       *Claims
	RefreshToken string
}

// SignInFunc inspects an http.Request for a valid response from the login authority
func (client *Client) SignInFunc(r *http.Request) (*SignInResponse, error) {
	var err error
	if err = r.ParseForm(); err != nil {
		return nil, err
	}

	var body struct {
		IDToken      string `schema:"id_token"`
		Code         string `schema:"code"`
		State        string `schema:"state"`
		SessionState string `schema:"session_state"`
	}
	if err = decoder.Decode(&body, r.PostForm); err != nil {
		return nil, err
	}

	var token *jwt.Token
	if token, err = jwt.ParseWithClaims(
		body.IDToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return client.getKey(token.Header["kid"].(string))
		},
	); err != nil {
		return nil, err
	}

	var refreshToken string
	if refreshToken, err = client.getRefreshToken(body.Code); err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return &SignInResponse{
			Claims:       claims,
			RefreshToken: refreshToken,
		}, nil
	}

	return nil, errors.New("error")
}

// MemberGroup is the object information for a group
type MemberGroup struct {
	DataType        string `json:"@odata.type"`
	Description     string `json:"description"`
	DisplayName     string `json:"displayName"`
	SecurityEnabled bool   `json:"securityEnabled"`
}
