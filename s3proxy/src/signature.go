package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

func calculateMD5Optimized(data []byte) string {
	// calculateMD5Optimized - function with buffering
	hash := md5.New()
	reader := bytes.NewReader(data)
	buf := make([]byte, 32*1024) // 32KB buffer

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			hash.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func calculateSHA256Optimized(data []byte) string {
	// calculateSHA256Optimized - function with buffering
	hash := sha256.New()
	reader := bytes.NewReader(data)
	buf := make([]byte, 32*1024) // 32KB buffer

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			hash.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func createSignedHeadersV4(headers http.Header) string {
	// create list of signed header. Must be lowercased, sorted and delimited with ';'
	var signedHeaders []string
	for key := range headers {
		signedHeaders = append(signedHeaders, strings.ToLower(key))
	}
	sort.Strings(signedHeaders)
	return strings.Join(signedHeaders, ";")
}

func createCanonicalHeadersV4(headers http.Header) string {
	// create canonical headers. Must be lowercased, sorted and delimited with ';'
	var canonicalHeaders []string
	for key, values := range headers {
		canonicalHeaders = append(canonicalHeaders, fmt.Sprintf("%s:%s", strings.ToLower(key), strings.Join(values, ",")))
	}
	sort.Strings(canonicalHeaders)
	return strings.Join(canonicalHeaders, "\n") + "\n"
}

func createCanonicalRequestV4(r *http.Request, payload []byte) string {
	// create canonical request
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-canonical-request

	method := r.Method

	canonicalURI := r.URL.Path

	var canonicalQuery string

	req_params, _ := url.ParseQuery(r.URL.RawQuery)
	var paramStrings []string
	for key, values := range req_params {
		if len(values) == 0 {
			paramStrings = append(paramStrings, fmt.Sprintf("%s=", url.QueryEscape(strings.ToLower(key))))
		} else {
			for _, value := range values {
				paramStrings = append(paramStrings, fmt.Sprintf("%s=%s", url.QueryEscape(strings.ToLower(key)), url.QueryEscape(value)))
			}
		}
	}

	sort.Strings(paramStrings)
	canonicalQuery = strings.Join(paramStrings, "&")

	canonicalHeaders := createCanonicalHeadersV4(r.Header)
	signedHeaders := createSignedHeadersV4(r.Header)
	payloadHash := calculateSHA256Optimized(payload)

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)
}

func getSigningKey(secretKey, date, region, service string) []byte {
	// create signing key
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#derive-signing-key
	kDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")

	return kSigning
}

func createStringToSignV4(r *http.Request, canonicalRequest, region, service string) string {
	// create string to sign
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-string-to-sign
	algorithm := "AWS4-HMAC-SHA256"
	date := r.Header.Get("X-Amz-Date")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date[:8], region, service)
	canonicalRequestHash := calculateSHA256Optimized([]byte(canonicalRequest))

	return fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		date,
		scope,
		canonicalRequestHash,
	)
}

func hmacSHA256(key []byte, data string) []byte {
	// hashing function
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func calculateSignatureV4(signingKey []byte, stringToSign string) string {
	// signature: sign stringToSign with signingKey
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}
