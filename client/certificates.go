package client

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gorilla/schema"
)

// using gorilla to encode a struct to form data, probably overkill but whateva
var encoder *schema.Encoder = schema.NewEncoder()
var b64Enc string = "b64"

//var binEnc string = "bin"

// We probably don't need the json field tags, but I put em here anyway
type certBody struct {
	Mode             string `json:"Mode"`
	CertRequest      string `json:"CertRequest"`
	CertAttrib       string `json:"CertAttrib"`
	FriendlyType     string `json:"FriendlyType"`
	TargetStoreFlags string `json:"TargetStoreFlags"`
	SaveCert         string `json:"SaveCert"`
}

func (c *ADCSClient) RequestCertificate(csr string, template string, attributes string) (*Certificates, error) {
	r, err := c.buildCertificateRequest(csr, template, attributes)

	if err != nil {
		return nil, err
	}

	resp, err := c.DoRequest(r)

	if err != nil {
		return nil, fmt.Errorf("certificate request failed: %v", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body from requesting certificates: %v", err)
	}

	reqID, err := getReqID(string(b))
	if err != nil {
		return nil, fmt.Errorf("failed to get request ID: %v", err)
	}
	certificates, err := c.RetrieveCertificates(reqID)
	if err != nil {
		return nil, fmt.Errorf("certificate downloads failed: %v", err)
	}
	return certificates, nil

}

func getReqID(data string) (string, error) {
	var reqID string
	r := regexp.MustCompile(`(certnew.*)\?ReqID=(?P<ReqID>\d+)&`)
	match := r.FindStringSubmatch(data)
	matchMap := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i > 0 && i <= len(match) {
			matchMap[name] = match[i]
		}
	}

	if _, ok := matchMap["ReqID"]; !ok {
		if strings.Contains(data, "Certificate Pending") {
			pendingRegex := regexp.MustCompile(`Your Request Id is (?P<ReqID>\d+).`)
			match := pendingRegex.FindStringSubmatch(data)
			return "", fmt.Errorf("certificate pending for request id %s", match[1])
		} else {
			r := regexp.MustCompile(`The disposition message is "([^"]+)`)
			dispoMatch := r.FindAllString(data, -1)
			if len(dispoMatch) != 2 {
				return "", fmt.Errorf("an unkown error occured")
			} else {
				return "", fmt.Errorf(dispoMatch[0])
			}
		}
	} else {
		reqID = matchMap["ReqID"]
	}

	return reqID, nil

}

func (c *ADCSClient) buildCertificateRequest(csr string, template TemplateName, attributes string) (*http.Request, error) {
	// build the payload
	certAttrib := "CertificateTemplate:" + string(template) + "\r\n"

	data := certBody{
		Mode:             "newreq",
		CertRequest:      csr,
		CertAttrib:       certAttrib,
		FriendlyType:     "Saved-Request Certificate",
		TargetStoreFlags: "0",
		SaveCert:         "yes",
	}

	form := url.Values{}
	err := encoder.Encode(data, form)

	if err != nil {
		return nil, fmt.Errorf("could not encode form data!: %v", err)
	}

	// Form the request
	url := "http://" + c.HostURL + "/certsrv/certfnsh.asp"
	r, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))

	// set important content-type request header
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		return nil, fmt.Errorf("could not create request: %v", err)
	}

	return r, nil

}

func (c *ADCSClient) RetrieveCertificates(reqId string) (*Certificates, error) {
	// TODO: these requests are so similiar and should be broken down to conform to more of DRY(Don't Repeat Yourself) style
	var certReturn Certificates
	//if encoding == nil {
	//	encoding = &b64Enc
	//}
	certReturn.ID = reqId

	queryStrings := url.Values{}
	queryStrings.Add("ReqID", reqId)
	queryStrings.Add("Enc", b64Enc)

	chainUrl := "http://" + c.HostURL + "/certsrv/certnew.p7b"
	certUrl := "http://" + c.HostURL + "/certsrv/certnew.cer"

	// get the full chain first
	chainReq, err := http.NewRequest("GET", chainUrl, nil)
	if err != nil {
		fatality := fmt.Errorf("failed to create request to download full certificate chain: %v", err)
		return nil, fatality
	}
	chainReq.URL.RawQuery = queryStrings.Encode()

	resp, err := c.DoRequest(chainReq)

	if err != nil {
		fatality := fmt.Errorf("failed to download full certificate chain: %v", err)
		return nil, fatality
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatality := fmt.Errorf("error reading response body: %v", err)
		return nil, fatality
	}
	respContentType := resp.Header.Get("Content-Type")
	if respContentType != "application/x-pkcs7-certificates" {
		return nil, checkDispostionError(string(body))
	} else {
		certReturn.CertificateChainB64 = string(body)
	}

	// now get the certificate
	certReq, err := http.NewRequest("GET", certUrl, nil)
	if err != nil {
		fatality := fmt.Errorf("could not create request to download certificate: %v", err)
		return nil, fatality
	}
	certReq.URL.RawQuery = queryStrings.Encode()
	certResp, err := c.DoRequest(certReq)
	certRespContentType := certResp.Header.Get("Content-Type")

	if err != nil {
		fatality := fmt.Errorf("failed to download certificate: %v", err)
		return nil, fatality
	}
	defer certResp.Body.Close()
	certBody, err := io.ReadAll(certResp.Body)

	if err != nil {
		fatality := fmt.Errorf("error reading response body: %v", err)
		return nil, fatality
	}

	// if you don't submit a user-agent this will be text/html. don't ask me why
	if certRespContentType != "application/pkix-cert" {
		return nil, checkDispostionError(string(certBody))
	} else {
		certReturn.CertificateB64 = string(certBody)
	}

	return &certReturn, nil

}

func checkDispostionError(data string) error {
	r := regexp.MustCompile(`The disposition message is "([^"]+)`)
	match := r.FindAllString(data, -1)
	if len(match) != 2 {
		return fmt.Errorf("an unkown error occured")
	} else {
		return fmt.Errorf(match[0])
	}
}
