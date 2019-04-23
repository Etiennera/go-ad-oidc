package goadoidc

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"github.com/mendsley/gojwk"
)

var decoder = schema.NewDecoder()
var httpClient = &http.Client{Timeout: 10 * time.Second}

const rootURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

func (client *Client) findKey(kid string) (*rsa.PublicKey, error) {
	for _, key := range client.keys {
		if key.Kid == kid {
			publicKey, err := key.DecodePublicKey()
			return publicKey.(*rsa.PublicKey), err
		}
	}
	return nil, errors.New("not found")
}

func (client *Client) getKey(kid string) (*rsa.PublicKey, error) {
	var key *rsa.PublicKey
	var err error
	if key, err = client.findKey(kid); err != nil {
		client.refreshKeys()
		return client.findKey(kid)
	}
	return key, nil
}

func (client *Client) refreshKeys() {
	var err error
	var openIDConfiguration map[string]interface{}

	if openIDConfiguration, err = getOpenIDConfiguration(client.tenantID); err != nil {
		return
	}

	var res *http.Response
	if res, err = httpClient.Get(openIDConfiguration["jwks_uri"].(string)); err != nil {
		return
	}
	defer res.Body.Close()

	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return
	}

	var keys struct {
		Keys []gojwk.Key `json:"keys"`
	}
	if err := json.Unmarshal(body, &keys); err != nil {
		return
	}

	client.keys = keys.Keys
}

func getOpenIDConfiguration(tenantID string) (map[string]interface{}, error) {
	configurationURL := "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration"

	var err error
	var res *http.Response
	var req *http.Request
	if req, err = http.NewRequest("GET", fmt.Sprintf(configurationURL, tenantID), nil); err != nil {
		return nil, err
	}
	if res, err = httpClient.Do(req); err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err = json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (client *Client) getRefreshToken(code string) (string, error) {
	var response struct {
		RefreshToken string `json:"refresh_token"`
	}

	values := url.Values{}
	values.Add("client_id", client.clientID)
	values.Add("scope", "User.Read Group.Read.All offline_access")
	values.Add("tenant", client.tenantID)
	values.Add("redirect_uri", client.redirectURI)
	values.Add("code", code)
	values.Add("grant_type", "authorization_code")
	values.Add("client_secret", client.clientSecret)

	if err := wwwEncodedPost(fmt.Sprintf(rootURL, client.tenantID), values, &response); err != nil {
		return "", err
	}

	return response.RefreshToken, nil
}

func (client *Client) getGroups(refreshToken string) ([]MemberGroup, error) {
	var err error
	var responseData struct {
		AccessToken string `json:"access_token"`
	}

	values := url.Values{}
	values.Add("client_id", client.clientID)
	values.Add("scope", "User.Read Group.Read.All offline_access")
	values.Add("tenant", client.tenantID)
	values.Add("redirect_uri", client.redirectURI)
	values.Add("grant_type", "refresh_token")
	values.Add("refresh_token", refreshToken)
	values.Add("client_secret", client.clientSecret)

	if err = wwwEncodedPost(fmt.Sprintf(rootURL, client.tenantID), values, &responseData); err != nil {
		return nil, err
	}

	var groupIDResponse struct {
		GroupIDs []string `json:"value"`
	}
	if err = jsonBearerPost(
		"https://graph.microsoft.com/v1.0/me/getMemberGroups",
		responseData.AccessToken,
		[]byte("{securityEnabledOnly:false}"),
		&groupIDResponse,
	); err != nil {
		return nil, err
	}

	var requestJSON []byte
	if requestJSON, err = json.Marshal(&struct {
		IDs   []string `json:"ids"`
		Types []string `json:"types"`
	}{
		IDs:   groupIDResponse.GroupIDs,
		Types: []string{"group"},
	}); err != nil {
		return nil, err
	}

	var groupResponse struct {
		Groups []MemberGroup `json:"value"`
	}
	if err = jsonBearerPost(
		"https://graph.microsoft.com/v1.0/directoryObjects/getByIds",
		responseData.AccessToken,
		requestJSON,
		&groupResponse,
	); err != nil {
		return nil, err
	}

	return groupResponse.Groups, nil
}

func jsonBearerPost(url, bearer string, j []byte, out interface{}) error {
	var err error
	var req *http.Request
	if req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(j))); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearer))

	var res *http.Response
	if res, err = httpClient.Do(req); err != nil {
		return err
	}
	defer res.Body.Close()

	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return err
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}

	return nil
}

func wwwEncodedPost(url string, values url.Values, out interface{}) error {
	var err error
	var req *http.Request
	if req, err = http.NewRequest("POST", url, strings.NewReader(values.Encode())); err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(values.Encode())))

	var res *http.Response
	if res, err = httpClient.Do(req); err != nil {
		return err
	}
	defer res.Body.Close()

	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return err
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}

	return nil
}
