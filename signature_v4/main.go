package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var credentials = Credentials{
	AccessKeyId:     "your_access_key_here",
	SecretAccessKey: "your_secret_key_here",
}
var host string = "s3.myserver.com"
var http_scheme string = "https"
var http_method string = "POST"
var amazonDate string = time.Now().UTC().Format("20060102T150405Z")

// for debug - one can use static datetime
// var amazonDate string = "20150915T124500Z"

// example for POST request
var http_path string = "/esbucket/?delete&x-purpose=SnapshotMetadata"

// var http_method string = "GET"

// example for GET request
// var http_path string = "/esbucket/"
// var http_path string = "/esbucket/?delimiter=%2F&list-type=2"

var region string = "us-west-1"
var service string = "s3"

// request's body example. We expect only plain xml text inside the payload, not binary data for POST requests.
// Otherwise we can be in a trouble

// var payload string = “		// empty fo GET/PUT requests
var payload string = `<Delete><Quiet>true</Quiet><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/data-_sDkZteNQU6BvaNciUCyaQ.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/master.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/</Key></Object></Delete>`
var content_type string = "application/xml"

// reference variables
// var credentials = Credentials{
// 	AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
// 	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
// }
// var host string = "my-precious-bucket.s3.amazonaws.com"
// var http_scheme string = "https"
// var http_method string = "GET"
// var http_path string = "/"
// var amazonDate string = "20150915T124500Z"

// // var amazonDate string = time.Now().UTC().Format("20060102T150405Z")
// var region string = "us-east-1"
// var service string = "s3"
// var payload string = ``

type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
}

func createSignatureV4(req *http.Request, credentials Credentials, payload, region, service string) string {
	// Step 1: create canonical request
	canonicalRequest := createCanonicalRequestV4(req, payload)

	// DEBUG
	fmt.Printf("Canonical Request:\n%s\n", canonicalRequest)
	fmt.Println("----------------------------------------------")

	// Step 2: create string to sign
	stringToSign := createStringToSignV4(req, canonicalRequest, region, service)

	// DEBUG
	fmt.Printf("StringToSign:\n%s\n", stringToSign)
	fmt.Println("----------------------------------------------")

	// Step 3: create signing key
	signingKey := getSigningKey(credentials.SecretAccessKey, req.Header.Get("X-Amz-Date")[:8], region, service)

	// DEBUG
	fmt.Printf("signingKey:%s\n", hex.EncodeToString(signingKey))
	fmt.Println("----------------------------------------------")

	// Step 4: create signature
	signature_v4 := calculateSignatureV4(signingKey, stringToSign)

	// DEBUG
	fmt.Printf("signature:%s\n", signature_v4)
	fmt.Println("----------------------------------------------")

	return signature_v4
}

func createCanonicalRequestV4(req *http.Request, payload string) string {
	method := req.Method
	// canonicalURI - everything after domain name till ? or end of URL
	canonicalURI := req.URL.Path

	var canonicalQuery string = ""

	// parse request parameters if they exist, and construct canonicalQuery
	req_params, _ := url.ParseQuery(req.URL.RawQuery)
	var paramStrings []string
	for key, values := range req_params {
		if len(values) == 0 {
			// add lowercased key with empty value, if no value passed (Amazon requires)
			paramStrings = append(paramStrings, fmt.Sprintf("%s=", url.QueryEscape(strings.ToLower(key))))
		} else {
			// add lowercased key with encoded value, if value passed (Amazon requires)
			for _, value := range values {
				paramStrings = append(paramStrings, fmt.Sprintf("%s=%s", url.QueryEscape(strings.ToLower(key)), url.QueryEscape(value)))
			}
		}
	}

	// sort all keys (Amazon requires)
	sort.Strings(paramStrings)
	canonicalQuery = strings.Join(paramStrings, "&")
	fmt.Printf("canonicalQuery:%s\n", canonicalQuery)
	fmt.Println("----------------------------------------------")

	// add all x-amz-* headers here if exists

	// create canonical headers
	canonicalHeaders := createCanonicalHeadersV4(req.Header)
	signedHeaders := createSignedHeadersV4(req.Header)

	payloadHash := calculateSHA256(payload)

	// construct canonical request finally
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)
}

func createCanonicalHeadersV4(headers http.Header) string {
	var canonicalHeaders []string
	for key, values := range headers {
		// headers in lowercase (Amazon requires)
		canonicalHeaders = append(canonicalHeaders, fmt.Sprintf("%s:%s", strings.ToLower(key), strings.Join(values, ",")))
	}
	// sort headers (Amazon requires)
	sort.Strings(canonicalHeaders)
	return strings.Join(canonicalHeaders, "\n") + "\n"
}

func createSignedHeadersV4(headers http.Header) string {
	var signedHeaders []string
	for key := range headers {
		// headers in lowercase (Amazon requires)
		signedHeaders = append(signedHeaders, strings.ToLower(key))
	}
	// sort headers (Amazon requires)
	sort.Strings(signedHeaders)
	return strings.Join(signedHeaders, ";")
}

func calculateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func calculateMD5(data string) string {
	hash := md5.Sum([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func createStringToSignV4(req *http.Request, canonicalRequest, region, service string) string {
	algorithm := "AWS4-HMAC-SHA256"
	date := req.Header.Get("X-Amz-Date")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date[:8], region, service)
	canonicalRequestHash := calculateSHA256(canonicalRequest)

	// construct string to sign
	return fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		date,
		scope,
		canonicalRequestHash,
	)
}

func getSigningKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request") // signingKey

	return kSigning
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func calculateSignatureV4(signingKey []byte, stringToSign string) string {
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}

func main() {
	// DEBUG
	fmt.Printf("payload:%s\n", payload)
	fmt.Printf("payload_hash (x-amz-content-sha256):%s\n", calculateSHA256(payload))
	fmt.Println("SHA256 of empty string is always:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	fmt.Println("----------------------------------------------")

	// create HTTP-request
	req, _ := http.NewRequest(http_method, http_scheme+"://"+host+http_path, strings.NewReader(payload))

	// add headers (Amazon requires)
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amazonDate)
	req.Header.Set("X-Amz-Content-Sha256", calculateSHA256(payload))

	// add additional headers for POST requests, bacause they contain non-empty payload.
	// we expect plain XML here, not binary data.
	// TODO: add checks for non-binary and non empty payload for POST requests
	if req.Method == "POST" {
		// Amazon requires:
		req.Header.Set("Content-Type", content_type)
		// Minio requires:
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		contentMD5 := calculateMD5(payload)
		req.Header.Set("Content-MD5", contentMD5)
		// how to check MD5 in bash: echo -ne "some_text_here" | openssl dgst -md5 -binary | openssl enc -base64
	}

	// get AWS Signature V4
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
	signature := createSignatureV4(req, credentials, payload, region, service)

	// add signature into Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
		credentials.AccessKeyId,
		req.Header.Get("X-Amz-Date")[:8],
		region,
		service,
		createSignedHeadersV4(req.Header),
		signature,
	))

	// DEBUG - Authorization header
	fmt.Println("Authorization Header:", req.Header.Get("Authorization"))

	// create and run HTTP-request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error while running request:", err)
		return
	}
	defer resp.Body.Close()

	// read servers's answer and print it
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error while reading server answer:", err)
		return
	}

	fmt.Println("==============================")
	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Body:", string(body))

}
