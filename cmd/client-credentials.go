package cmd

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2/clientcredentials"
	"io/ioutil"
	"net/http"
	"os"
)

// clientCredentialsCmd represents the client-credentials command
var clientCredentialsCmd = &cobra.Command{
	Use: "client-credentials",

	Run: func(cmd *cobra.Command, args []string) {
		runClientCredentialsCLI()
	},
}

func init() {
	rootCmd.AddCommand(clientCredentialsCmd)
}

func runClientCredentialsCLI() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuerURL := os.Getenv("ISSUER_URL")
	apiURL := os.Getenv("API_URL")
	scopes, _ := os.LookupEnv("SCOPES")
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Printf("Client Secret: %s\n", clientSecret)
	provider, err := oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		panic(err)
	}
	if scopes == "" {
		scopes = "openid"
	}
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{scopes},
		TokenURL:     provider.Endpoint().TokenURL,
	}

	token, err := config.Token(context.Background())
	if err != nil {
		fmt.Printf("Error retrieving token: %s\n", err)
		return
	}

	client := &http.Client{}

	// Create an HTTP request with the Authorization header containing the access token
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Request failed with status code: %d\n", resp.StatusCode)
		return
	}

	// Print the response body to the terminal
	fmt.Println("Response:")
	fmt.Println(string(body))

}
