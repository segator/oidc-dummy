package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var loginFormTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ROPC Login</title>
</head>
<body>
	<h1>Resource Owner password</h1>
    <form method="post" action="/ropc/auth">
        <b>Username:</b> <input type="text" name="username">
		<br/>
		<br/>
        <b>Password:</b> <input type="password" name="password">
		<br/>
        <button type="submit">Login</button>
    </form>
</body>
</html>
`
var notAuthorizedHome = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h1>Unauthorized</h1><br/>
	<a href="/auth/login">Login with Authorization Code Grant</a>
	<br/>
	<a href="/ropc/login">Login with Resource Owner Password Grant</a>
</body>
</html>
`
var oauth2Config *oauth2.Config
var provider *oidc.Provider
var verifier *oidc.IDTokenVerifier
var issuerURL string
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve your application",
	Long: `Start the server to serve your application. For example:

Use the 'serve' command to start serving your application on a specified port.`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		clientID, _ := os.LookupEnv("CLIENT_ID")
		clientSecret, _ := os.LookupEnv("CLIENT_SECRET")
		redirectURL, _ := os.LookupEnv("REDIRECT_URL")
		issuerURL, _ = os.LookupEnv("ISSUER_URL")

		scopes, _ := os.LookupEnv("SCOPES")
		provider, err = oidc.NewProvider(context.Background(), issuerURL)
		if err != nil {
			panic(err)
		}
		verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

		if redirectURL == "" {
			redirectURL = "http://localhost:9999/auth/callback"
		}

		if scopes == "" {
			scopes = "openid profile"
		}
		oauth2Config = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{scopes},
		}
		serve()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

}

func serve() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusFound)
	})

	// Resource Owner Password Credentials grant type endpoint
	http.HandleFunc("/ropc/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, loginFormTemplate)
	})
	http.HandleFunc("/ropc/auth", handleROPCAuth)

	// Authorization Code grant type endpoint
	http.HandleFunc("/auth/login", handleAuthCodeGrant)
	http.HandleFunc("/auth/callback", handleAuthCodeCallback)
	http.HandleFunc("/home", handleHome)
	http.HandleFunc("/api/home", handleApiHome)
	http.HandleFunc("/logout", handleLogout)

	// Start the server
	http.ListenAndServe(":9999", nil)
}

func handleROPCAuth(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	token, err := getTokenUsingPasswordGrant(username, password)
	if err != nil {
		http.Error(w, "Failed to get token", http.StatusInternalServerError)
		return
	}
	setSecureCookie(w, "auth_token", token)
	http.Redirect(w, r, "/home", http.StatusFound)
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline), http.StatusFound)
}

func handleAuthCodeCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	if token != nil {
		setSecureCookie(w, "auth_token", token.AccessToken)
		// Redirect to the home page
		http.Redirect(w, r, "/home", http.StatusFound)
	} else {
		http.Error(w, "Failed to get the token", http.StatusInternalServerError)
	}
}
func handleApiHome(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized: Invalid Authorization Header")
		return
	}
	accessTokenString := strings.TrimPrefix(authHeader, "Bearer ")
	accessToken := verifyAccessToken(w, accessTokenString)
	user, err := extractUser(accessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
	}

	fmt.Fprint(w, fmt.Sprintf("Hello %s", user))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := getCookie(r, "auth_token")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, notAuthorizedHome)
		return
	}

	accessToken := verifyAccessToken(w, cookie.Value)
	user, err := extractUser(accessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
	}

	fmt.Fprint(w, fmt.Sprintf("<h1>Hello %s</h1><br/><a href='/logout'>Logout</a>", user))
}

func extractUser(token *jwt.Token) (string, error) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		user := fmt.Sprint(claims["sub"])
		username := claims["preferred_username"]
		if username != nil {
			user = username.(string)
		}
		return user, nil

	}
	return "", fmt.Errorf("not valid claims")
}

func verifyAccessToken(w http.ResponseWriter, accessToken string) *jwt.Token {
	token := &oauth2.Token{AccessToken: accessToken}
	token.Valid()

	jwks, err := keyfunc.Get(fmt.Sprintf("%s/protocol/openid-connect/certs", issuerURL), keyfunc.Options{}) // See recommended options in the examples directory.
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err)
	}

	parsedToken, err := jwt.Parse(token.AccessToken, jwks.Keyfunc)
	if err != nil {
		fmt.Fprint(w, "Invalid access")
	}
	return parsedToken
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, "auth_token")
	clearCookie(w, "id_token")

	logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout?client_id=%s&post_logout_redirect_uri=%s", issuerURL, oauth2Config.ClientID, url.QueryEscape("http://localhost:9999/"))
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
	//http.Redirect(w, r, "/", http.StatusFound)

}

// Additional functions such as setSecureCookie, clearCookie, getCookie, getUserInfo would be defined here...
func setSecureCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // in production, set to true
		MaxAge:   3600, // 1 hour
	})
}

// Helper function to clear a cookie
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func getCookie(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(name)
}

func getTokenUsingPasswordGrant(username, password string) (string, error) {
	data := url.Values{
		"grant_type":    {"password"},
		"username":      {username},
		"password":      {password},
		"client_id":     {oauth2Config.ClientID},
		"client_secret": {oauth2Config.ClientSecret},
		"scope":         {strings.Join(oauth2Config.Scopes, " ")},
	}

	req, err := http.NewRequest("POST", provider.Endpoint().TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	return result["access_token"].(string), nil
}
