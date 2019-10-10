package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
)

// SSHConfig stores the parameters needed for a SSH command
type SSHConfig struct {
	Profile string
}

// ConfigureSSH configures the ssh command with arguments and flags
func ConfigureSSH(app *kingpin.Application, config *GlobalConfig) {

	sshConfig := SSHConfig{}

	cmd := app.Command("ssh", "Sign a SSH certificate")

	cmd.Arg("profile", "Name of the profile").
		StringVar(&config.Profile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		SSHCommand(app, config, &sshConfig)
		return nil
	})
}

// SSHCommand exchanges temporary credentials for an AWS Console signin url
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func SSHCommand(app *kingpin.Application, config *GlobalConfig, sshConfig *SSHConfig) {

	// Retrieve credentials from current session. This will try and get credentials
	// using awsgogh itself if configured in ~/.aws/config.
	val, err := config.Session.Config.Credentials.Get()
	if err != nil {
		app.Fatalf("Unable to get credentials for profile: %s", config.Profile)
	}

	credentialData := signinSession{
		SessionID:    val.AccessKeyID,
		SessionKey:   val.SecretAccessKey,
		SessionToken: val.SessionToken,
	}
	credentialJSON, err := json.Marshal(&credentialData)
	if err != nil {
		app.Fatalf("Unable to marshal credentials for profile: %s", config.Profile)
	}

	// Create the federation URL to exchange access keys for a session token
	tokenURL, _ := url.Parse("https://signin.aws.amazon.com/federation")
	tokenQuery := url.Values{}
	tokenQuery.Set("Action", "getSigninToken")
	tokenQuery.Set("Session", string(credentialJSON))
	tokenURL.RawQuery = tokenQuery.Encode()

	var client = &http.Client{
		Timeout: time.Second * 60,
	}
	resp, err := client.Get(tokenURL.String())
	if err != nil {
		app.Fatalf("Unable to get signin token for profile: %s", config.Profile)
	} else if resp.StatusCode != 200 {
		app.Fatalf("GetSigninToken returned %d instead of 200 for profile: %s", resp.StatusCode, config.Profile)
	}
	defer resp.Body.Close()

	token := signinToken{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		app.Fatalf("Unable to decode GetSigninToken response for profile: %s", config.Profile)
	}

	// Create the federation URL to exchange the session token for a ssh URL
	sshURL, _ := url.Parse("https://signin.aws.amazon.com/federation")
	sshQuery := url.Values{}
	sshQuery.Set("Action", "ssh")
	sshQuery.Set("Destination", "https://console.aws.amazon.com/")
	sshQuery.Set("SigninToken", token.SigninToken)
	sshURL.RawQuery = sshQuery.Encode()

	fmt.Println(sshURL)
}
