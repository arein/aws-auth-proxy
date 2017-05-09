package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"net/http"
	"net/url"
	"github.com/coreos/pkg/flagutil"
	"github.com/AdRoll/goamz/aws"
)

func main() {
	var (
		auth          aws.Auth
		targetURL     url.URL
		listenAddress string
		serviceName   string
		region        aws.Region
	)
	const flagEnvPrefix = "AWS_AUTH_PROXY"

	fs := flag.NewFlagSet("aws-auth-proxy", flag.ExitOnError)
	
	var accessKey string
	var secretKey string
	var token string
	var expiration string
	fs.StringVar(&accessKey, "access-key", "", "aws access key id")
	fs.StringVar(&secretKey, "secret-key", "", "aws secret access key")
	fs.StringVar(&token, "token", "", "aws security token")
	fs.StringVar(&expiration, "expiration", "", "aws token expiration")
	fs.StringVar(&serviceName, "service-name", "", "aws service name")
	var regionName string
	fs.StringVar(&regionName, "region-name", "", "aws region name")
	fs.StringVar(&targetURL.Host, "upstream-host", "", "host or host:port for upstream endpoint")
	fs.StringVar(&targetURL.Scheme, "upstream-scheme", "https", "scheme for upstream endpoint")
	fs.StringVar(&listenAddress, "listen-address", ":8080", "address for proxy to listen on")

	if err := flagutil.SetFlagsFromEnv(fs, flagEnvPrefix); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) >= 2 && os.Args[1] == "--help" {
		fs.PrintDefaults()
		fmt.Printf("\nflagutil prefix is '%s'\n", flagEnvPrefix)
		fmt.Printf("example:\n\t-access-key=xxx OR export %s_ACCESS_KEY=xxx\n", flagEnvPrefix)
		os.Exit(0)
	}
	fs.Parse(os.Args[1:])
	
	
	t, err := time.Parse(time.RFC3339Nano, expiration)
	if err != nil {
		panic(err)
	}

	region = aws.GetRegion(regionName)
	fmt.Println(accessKey)
	fmt.Println(secretKey)
	fmt.Println(token)
	auth = *aws.NewAuth(accessKey, secretKey, token, t)
	signer := aws.NewV4Signer(auth, serviceName, region)

	proxyHandler := &AWSProxy{
		TargetURL: &targetURL,
		Signer:    signer,
	}
	fmt.Printf("Listening on %s\n", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, proxyHandler))

}

type AWSProxy struct {
	TargetURL *url.URL
	Signer    *aws.V4Signer
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}
func (h *AWSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	respondError := func(err error) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}
	proxyURL := *r.URL
	proxyURL.Host = h.TargetURL.Host
	proxyURL.Scheme = h.TargetURL.Scheme

	req, err := http.NewRequest(
		r.Method,
		proxyURL.String(),
		r.Body,
	)

	if err != nil {
		respondError(err)
		return
	}

	req.Header.Set("X-Amz-Date", time.Now().UTC().Format(aws.ISO8601BasicFormat))

	h.Signer.Sign(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		respondError(err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)

	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		respondError(err)
		return
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(buf.Bytes())
}
