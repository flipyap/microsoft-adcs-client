package client

import (
	"fmt"
	"log"
	"net/http"
	"os"

	//"time"

	krbClient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/pkg/profile"
	httpntlm "github.com/vadimi/go-http-ntlm/v2"
)

// HostURL - Default Hashicups URL
const HostURL string = "http://aus-ca-prd-01.q2dc.local"

// Client -
type ADCSClient struct {
	HostURL      string
	SpnegoClient *spnego.Client
	NtlmClient   *http.Client
	logger       *log.Logger
	UseNtlm      bool
}

type ClientConfig struct {
	Host     string
	Username string
	Password string
	Krb5Conf string
	Realm    string
	Ntlm     bool
}

// NewClient -
func NewClient(ClientConfig *ClientConfig) (*ADCSClient, error) {
	l := log.New(os.Stderr, "ADCS Plugin: ", log.Ldate|log.Ltime|log.Lshortfile)
	var cl *krbClient.Client
	var nl *http.Client
	var conf *config.Config
	var err error

	defer profile.Start(profile.TraceProfile).Stop()

	// we should allow keytab auth or username/password !!!!!
	// Load the keytab
	//kb, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	//kt := keytab.New()
	//err := kt.Unmarshal(kb)
	//if err != nil {
	//	l.Fatalf("could not load client keytab: %v", err)
	//}

	// Try to load the client krb5 config
	if !ClientConfig.Ntlm {

		if ClientConfig.Krb5Conf != "" {
			conf, err = config.NewFromString(ClientConfig.Krb5Conf)
			if err != nil {
				return nil, fmt.Errorf("could not load krb5.conf received: %v", err)
			}
		} else if os.Getenv("KRB5CONF") != "" {
			conf, err = config.NewFromString(ClientConfig.Krb5Conf)
			if err != nil {
				return nil, fmt.Errorf("could not load krb5.conf received in environment variable: %v", err)
			}
		} else {
			// if no string value given and no env var set, try load from path as last resort
			conf, err = config.Load("/etc/krb5.conf")
			if err != nil {
				return nil, fmt.Errorf("could not load krb5.conf from config file /etc/krb5.conf: %v", err)
			}
		}
		if conf != nil {
			// TODO: do not just rely on the deafult realm
			if conf.LibDefaults.DefaultRealm == "" {
				return nil, fmt.Errorf("could not get default_realm from krb5 configuration")
			}
			// create client with username password
			cl = krbClient.NewWithPassword(ClientConfig.Username, conf.LibDefaults.DefaultRealm, ClientConfig.Password, conf, krbClient.Logger(l), krbClient.DisablePAFXFAST(true))
			// Log in the client
			err = cl.Login()
			if err != nil {
				return nil, fmt.Errorf("could not login client with kerberos authentication: %v", err)
			}
		}

	} else {
		// Do the ntlm auth
		nl = &http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:   "",
				User:     ClientConfig.Username,
				Password: ClientConfig.Password,
			},
		}
	}

	// Create the client with the keytab
	//cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, conf, client.Logger(l), client.DisablePAFXFAST(true))

	c := ADCSClient{
		SpnegoClient: spnego.NewClient(cl, nil, ""),
		NtlmClient:   nl,
		HostURL:      ClientConfig.Host,
		UseNtlm:      ClientConfig.Ntlm,
		logger:       l,
	}

	return &c, nil

}

func (c *ADCSClient) DoRequest(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Add important header for correct response content-type
	req.Header.Add("User-agent", "Mozilla/5.0 Terraform ADCS Provider ")
	// Make the request
	if !c.UseNtlm {
		resp, err = c.SpnegoClient.Do(req)
	} else {
		resp, err = c.NtlmClient.Do(req)
	}

	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status error: %v", resp.StatusCode)
	}
	return resp, err
}
