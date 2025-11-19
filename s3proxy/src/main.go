package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var CurrentVersion string = "1.0.17"

func printMemStats() {
	TraceLogger.Println("Where:", "printMemStats")
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	TraceLogger.Printf("Alloc = %v MiB, TotalAlloc = %v MiB, Sys = %v MiB, NumGC = %v\n", m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}

func startPprofServer() {
	/* localhost:6060 is for profiling memory consumption (PPROF) for debug
	   curl -o /tmp/mem.pprof http://localhost:6060/debug/pprof/heap
	   go tool pprof /tmp/mem.pprof

	   top - shows top memmory usage functions
	   list <function_name> - show memory for specific function
	*/

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s CONFIG_FILE\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "HTTP proxy that authenticates S3 requests\n")
}

type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

type BucketInfo struct {
	Name        string
	VirtualHost bool
	Config      *BucketConfig
}

type ProxyHandler struct {
	config          *Config
	client          *http.Client
	credentialCache *CredentialCache
}

const S3ProxyMetadataHeader = "X-Amz-Meta-S3proxy"
const S3ProxyMetadataVersion = byte(0x00)

func IsMultipartRequest(r *http.Request) bool {
	// check if we have one or more multipart parameters in URL
	query := r.URL.Query()

	// list of parameters to check
	requiredParams := []string{"uploads", "uploadId"}

	for _, param := range requiredParams {
		if _, ok := query[param]; ok {
			return true
		}
	}

	return false
}

func (h *ProxyHandler) GetBucketSecurityCredentials(c *BucketConfig) (*Credentials, error) {
	TraceLogger.Println("Where:", "GetBucketSecurityCredentials")
	if c.AccessKeyId != "" {
		return &Credentials{
			AccessKeyId:     c.AccessKeyId,
			SecretAccessKey: c.SecretAccessKey,
		}, nil
	}

	TraceLogger.Println("Where:", "end GetBucketSecurityCredentials")
	return h.credentialCache.GetRoleCredentials()
}

func (h *ProxyHandler) GetBucketInfo(r *http.Request) *BucketInfo {
	TraceLogger.Println("Where:", "GetBucketInfo")

	var bucketName string
	var bucketVirtualHost bool

	requestHost := r.Host
	if idx := strings.Index(requestHost, ":"); idx != -1 {
		requestHost = requestHost[:idx]
	}

	configDomain := h.config.Server.AwsDomain
	if idx := strings.Index(configDomain, ":"); idx != -1 {
		configDomain = configDomain[:idx]
	}

	TraceLogger.Printf("GetBucketInfo DEBUG: requestHost='%s', configDomain='%s'", requestHost, configDomain)

	// check virtual host style
	isExplicitVirtualHost := false
	if idx := strings.Index(requestHost, "."); idx != -1 {
		potentialBucket := requestHost[:idx]
		if !isIPAddress(potentialBucket) && potentialBucket != configDomain && requestHost != configDomain {
			bucketName = potentialBucket
			bucketVirtualHost = true
			isExplicitVirtualHost = true
			InfoLogger.Printf("Explicit virtual host style - bucket: %s", bucketName)
		}
	}

	// use path style if not virtual host style
	if !isExplicitVirtualHost {
		tokens := strings.Split(r.URL.Path, "/")
		for _, t := range tokens {
			if t == "" {
				continue
			}
			bucketName = t
			break
		}
		if bucketName != "" {
			InfoLogger.Printf("Path style - bucket: %s", bucketName)
		}
	}

	if bucketName == "" {
		InfoLogger.Printf("List buckets request")
		return &BucketInfo{
			Name:        "",
			VirtualHost: false,
			Config:      nil,
		}
	}

	config := h.config.Buckets[bucketName]
	if config == nil {
		InfoLogger.Printf("Bucket '%s' not in config, but allowing request", bucketName)
		return &BucketInfo{
			Name:        bucketName,
			VirtualHost: bucketVirtualHost,
			Config:      nil,
		}
	}

	return &BucketInfo{
		Name:        bucketName,
		VirtualHost: bucketVirtualHost,
		Config:      config,
	}
}

func isIPAddress(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.Contains(s, ".")
}

func (h *ProxyHandler) PreRequestEncryptionHook(r *http.Request, innerRequest *http.Request, info *BucketInfo) (*CountingHash, error) {
	TraceLogger.Println("Where:", "PreRequestEncryptionHook")
	// if this is not PUT request and info.Config.EncryptionKey is not set, then we do not need encrypt it
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" || r.Method != "PUT" {
		return nil, nil
	}

	// if we are here, when encryption is required for PUT request

	// if we have x-amz-copy-source header, then we start PUT request for metadata refresh
	// It doesn't contain Body, only headers, so we do not need to encrypt it
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-copy-source") {
			return nil, nil
		}
	}

	// encrypt request body here
	encryptedInput, extralen, err := SetupWriteEncryption(r.Body, info)

	if err != nil {
		return nil, err
	}

	// Since encryption transforms the data, after the inner request succeeds,
	// we'll match the MD5s of the transformed data, and mangle the etag in the
	// response we send to the client with the MD5 of the untransformed data if
	// they match.
	innerBodyHash := NewCountingHash(md5.New())
	teereader := io.TeeReader(encryptedInput, innerBodyHash)
	innerRequest.Body = io.NopCloser(teereader)

	// remove Content-Md5 from headers, bacause encryption is changing Body
	innerRequest.Header.Del("Content-Md5")

	if length := innerRequest.ContentLength; length != -1 {
		innerRequest.ContentLength += extralen
		innerRequest.Header.Set("Content-Length", strconv.FormatInt(innerRequest.ContentLength, 10))
	}

	InfoLogger.Print("Encrypting the request")

	TraceLogger.Println("Where:", "end PreRequestEncryptionHook")
	return innerBodyHash, nil
}

func (h *ProxyHandler) PostRequestEncryptionHook(r *http.Request, innerResponse *http.Response, info *BucketInfo) (io.ReadCloser, error) {
	TraceLogger.Println("Where:", "PostRequestEncryptionHook")

	// incoming parameters DEBUG
	if info == nil {
		TraceLogger.Printf("PostRequestEncryptionHook: info is nil")
	} else {
		TraceLogger.Printf("PostRequestEncryptionHook: bucket=%s, config=%v", info.Name, info.Config != nil)
	}

	// check for list requests, even no bucket configured
	isListRequest := strings.HasSuffix(r.URL.Path, "/") ||
		strings.Contains(r.URL.RawQuery, "list-type=") ||
		strings.Contains(r.URL.RawQuery, "delimiter=") ||
		strings.Contains(r.URL.RawQuery, "prefix=") ||
		r.URL.Path == "/" // root path - list buckets
		//      (innerResponse != nil && innerResponse.Header.Get("Content-Type") == "application/xml")

	if isListRequest {
		TraceLogger.Printf("List request detected (path=%s, query=%s), skipping PostRequestEncryptionHook processing, returning original response", r.URL.Path, r.URL.RawQuery)
		return innerResponse.Body, nil
	}

	if info == nil || info.Config == nil {
		TraceLogger.Printf("PostRequestEncryptionHook: no bucket config, returning original response")
		return innerResponse.Body, nil
	}

	// if encryption disabled for bucket
	if info.Config.EncryptionKey == "" {
		TraceLogger.Printf("PostRequestEncryptionHook: encryption disabled for bucket")
		return innerResponse.Body, nil
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		// for PUT and POST requests: return original request Body
		TraceLogger.Printf("PostRequestEncryptionHook: not GET/HEAD method")
		return innerResponse.Body, nil
	}

	if innerResponse.StatusCode >= 300 {
		TraceLogger.Printf("PostRequestEncryptionHook: status code >= 300")
		return innerResponse.Body, nil
	}

	InfoLogger.Print("Decrypting the response")

	// If we had cached encrypted metadata, decrypt it and return it to the client
	if encryptedMetadata := innerResponse.Header.Get(S3ProxyMetadataHeader); encryptedMetadata != "" {
		var metadataBytes []byte
		_, err := fmt.Sscanf(encryptedMetadata, "%x", &metadataBytes)

		if err != nil {
			return nil, err
		}

		decReader, _, err := SetupReadEncryption(bytes.NewReader(metadataBytes), info)

		if err != nil {
			return nil, err
		}

		metadata, err := UnserializeObjectMetadata(decReader)

		if err != nil {
			return nil, err
		}

		delete(innerResponse.Header, S3ProxyMetadataHeader)
		innerResponse.Header.Set("Etag", metadata.Etag)
		innerResponse.Header.Set("Content-Length", fmt.Sprintf("%d", metadata.Size))

		InfoLogger.Printf("Overwrote the response headers with the cached version (Etag: %s, Content-Length: %d)", metadata.Etag, metadata.Size)
	}

	if r.Method == "HEAD" {
		return innerResponse.Body, nil
	}

	decryptedReader, minuslen, err := SetupReadEncryption(innerResponse.Body, info)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := decryptedReader.Close(); closeErr != nil {
			ErrorLogger.Printf("Error closing decrypted reader: %v", closeErr)
		}
	}()

	if length := innerResponse.ContentLength; length != -1 {
		innerResponse.ContentLength -= minuslen
		innerResponse.Header.Set("Content-Length", strconv.FormatInt(innerResponse.ContentLength, 10))
	}

	TraceLogger.Println("Where:", "end PostRequestEncryptionHook")
	return decryptedReader, nil
}

func IsValidXML(data []byte) bool {
	return xml.Unmarshal(data, new(interface{})) == nil
}

func (h *ProxyHandler) SignRequestV4(r *http.Request, info *BucketInfo, bodyData []byte) error {
	TraceLogger.Println("Where:", "SignRequestV4")

	// DEBUG
	if info == nil {
		TraceLogger.Printf("SignRequestV4: info is nil - cannot sign request")
		return nil
	}

	TraceLogger.Printf("SignRequestV4: signing request for bucket=%s, hasConfig=%v", info.Name, info.Config != nil)

	var credentials *Credentials
	var region string

	// use credentials from first configured bucket, if bucket not found in config
	if info.Config == nil {
		TraceLogger.Printf("SignRequestV4: bucket '%s' not in config, looking for default credentials", info.Name)

		if len(h.config.Buckets) > 0 {
			for _, bucketConfig := range h.config.Buckets {
				TraceLogger.Printf("SignRequestV4: using credentials from configured bucket for '%s'", info.Name)
				credentials = &Credentials{
					AccessKeyId:     bucketConfig.AccessKeyId,
					SecretAccessKey: bucketConfig.SecretAccessKey,
				}
				// use region for non configured buckets
				region = bucketConfig.Region
				break
			}
		} else {
			TraceLogger.Printf("SignRequestV4: no buckets in config, cannot sign request for '%s'", info.Name)
			return fmt.Errorf("no credentials available for bucket '%s'", info.Name)
		}
	} else {
		// check if we have credentials configured
		var err error
		credentials, err = h.GetBucketSecurityCredentials(info.Config)
		if err != nil {
			return err
		}
		region = info.Config.Region
	}

	return h.signRequestInternal(r, credentials, region, bodyData)
}

// Internal signing function
func (h *ProxyHandler) signRequestInternal(r *http.Request, credentials *Credentials, region string, bodyData []byte) error {
	TraceLogger.Println("Where:", "signRequestInternal")

	if region == "" {
		region = "us-east-1"
	}
	service := "s3"

	TraceLogger.Println("Where:", "signRequestInternal 1")
	// AWS signature V4 canonical request
	// first - remove unnecessary headers
	headers_to_ignore := []string{"authorization", "connection", "x-amzn-trace-id", "user-agent", "expect", "presigned-expires", "range", "proxy-connection", "accept-encoding"}

	for _, header_to_remove := range headers_to_ignore {
		r.Header.Del(header_to_remove)
	}

	// remove Content-Length from all listing requests
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "DELETE" {
		r.Header.Del("Content-Length")
		TraceLogger.Printf("Removed Content-Length header from %s request", r.Method)
	}

	TraceLogger.Println("Where:", "before adding headers")
	// next - add the necessary headers
	content_type := r.Header.Get("Content-Type")
	content_length := r.Header.Get("Content-Length")

	TraceLogger.Println("Where:", "before adding Content-Type, Content-Length, Content-Md5")
	// add Content-Type, Content-Length, Content-Md5 for POST requests
	if r.Method == "POST" {
		if content_type == "" {
			content_type = "text/plain"
			if len(bodyData) > 0 {
				if IsValidXML(bodyData) {
					content_type = "application/xml"
				}
			}
			r.Header.Set("Content-Type", content_type)
		}

		if content_length == "" {
			content_length = fmt.Sprint(len(bodyData))
			r.Header.Set("Content-Length", content_length)
		}

		content_md5 := r.Header.Get("Content-Md5")
		if content_md5 == "" {
			content_md5 = calculateMD5Optimized(bodyData)
			r.Header.Set("Content-Md5", content_md5)
		}
	}

	TraceLogger.Println("Where:", "after adding Content-Type, Content-Length, Content-Md5")

	// add Date and/or X-Amz-Date header. The must be one of them, but may be both. In this case Date is winner
	amazonDate := r.Header.Get("Date")
	if amazonDate == "" && r.Header.Get("x-amz-date") == "" {
		amazonDate = time.Now().UTC().Format("20060102T150405Z")
		r.Header.Set("Date", amazonDate)
	}

	TraceLogger.Println("Where:", "before X-Amz-Content-Sha256")
	// adding X-Amz-Content-Sha256 header
	r.Header.Set("X-Amz-Content-Sha256", calculateSHA256Optimized(bodyData))
	TraceLogger.Println("Where:", "after X-Amz-Content-Sha256")

	// adding x-amz-security-token
	if credentials.Token != "" {
		r.Header.Add("x-amz-security-token", credentials.Token)
	}

	// add all others x-amz-* headers
	canonicalizedAmzHeaders := bytes.NewBuffer(nil)
	amzHeaders := []string{}

	// loop only keys, we do not need values
	for k := range r.Header {
		if !strings.HasPrefix(strings.ToLower(k), "x-amz-") {
			continue
		}
		amzHeaders = append(amzHeaders, k)
	}

	sort.Strings(amzHeaders)

	for _, k := range amzHeaders {
		canonicalizedAmzHeaders.WriteString(strings.ToLower(k))
		canonicalizedAmzHeaders.WriteString(":")
		canonicalizedAmzHeaders.WriteString(strings.Join(r.Header[k], ","))
		canonicalizedAmzHeaders.WriteString("\n")
	}

	// add Host header
	r.Header.Set("Host", r.URL.Host)

	TraceLogger.Println("Where:", "before createCanonicalRequestV4")
	// step 1: create canonical request
	canonicalRequest := createCanonicalRequestV4(r, bodyData)

	TraceLogger.Printf("Canonical Request:\n%s\n", canonicalRequest)
	TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before createStringToSignV4")
	// step 2: create string to sign
	stringToSign := createStringToSignV4(r, canonicalRequest, region, service)

	TraceLogger.Printf("StringToSign:\n%s\n", stringToSign)
	TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before getSigningKey")
	// step 3: calculate key for signature
	signingKey := getSigningKey(credentials.SecretAccessKey, r.Header.Get("X-Amz-Date")[:8], region, service)

	TraceLogger.Printf("signingKey:%s\n", hex.EncodeToString(signingKey))
	TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before calculateSignatureV4")
	// step 4: calculate signature, based on key and string to sign
	signature_v4 := calculateSignatureV4(signingKey, stringToSign)

	TraceLogger.Printf("signature:%s\n", signature_v4)
	TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before Authorization header")
	// add Authorization header
	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
		credentials.AccessKeyId,
		r.Header.Get("X-Amz-Date")[:8],
		region,
		service,
		createSignedHeadersV4(r.Header),
		signature_v4,
	))

	TraceLogger.Println("Where:", "end signRequestInternal")
	return nil
}

func connectResponseOK(w http.ResponseWriter, format string, args ...interface{}) {
	// return 200 OK, if whis is CONNECT method (for https and proxy authentication)
	// we do not support auth yet
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, format, args...)
	InfoLogger.Printf(format, args...)
}

func failRequest(w http.ResponseWriter, statusCode int, format string, args ...interface{}) {
	const ErrorFooter = "\n\nGreetings, the S3Proxy\n"

	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, format+ErrorFooter, args...)
	ErrorLogger.Printf(format, args...)
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// show memory status
	TraceLogger.Println("Where:", "start ServeHTTP")
	printMemStats()

	// panic protection
	defer func() {
		if err := recover(); err != nil {
			ErrorLogger.Printf("Recovered from panic: %v", err)
			failRequest(w, http.StatusInternalServerError, "Internal server error")
		}
	}()

	// function for incoming request processing
	InfoLogger.Printf("%s %s (Host: %s)", r.Method, r.URL, r.Host)

	// answer 200 OK if CONNECT recieved
	if r.Method == "CONNECT" {
		connectResponseOK(w, "Connection Established")
		return
	}

	// we do not support multiparts
	if IsMultipartRequest(r) && (r.Method == "PUT" || r.Method == "POST") {
		fmt.Println("IsMultipartRequest = true. end with http.StatusNotImplemented")
		failRequest(w, http.StatusNotImplemented, "Multiparts are not supported: %s", r.Method)
		return
	}

	// read bucket configuration
	info := h.GetBucketInfo(r)

	if info == nil {
		InfoLogger.Print("List buckets request (no specific bucket)")
	} else if info.Config == nil {
		InfoLogger.Printf("Handling request for unconfigured bucket: %s", info.Name)
	} else {
		InfoLogger.Printf("Handling request for configured bucket: %s", info.Name)
	}

	defer func() {
		if closeErr := r.Body.Close(); closeErr != nil {
			ErrorLogger.Printf("Error closing request body: %v", closeErr)
		}
	}() // force to close body if error happens

	// buffer for original request body
	var originalBodyData bytes.Buffer
	originalBodyHashStatic := NewCountingHash(md5.New())
	// copy r.Body into originalBodyData and originalBodyHashStatic (Heavy operation, depends on body size of request)
	TraceLogger.Println("Where:", "before originalBodyData copy")
	teereader := io.TeeReader(r.Body, io.MultiWriter(&originalBodyData, originalBodyHashStatic))
	buf := make([]byte, 1<<20) // 1MB buffer
	_, err := io.CopyBuffer(io.Discard, teereader, buf)
	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Failed to read original request body: %s", err)
		return
	}
	TraceLogger.Println("Where:", "after originalBodyData copy")

	// restore r.Body for further usage
	r.Body = io.NopCloser(&originalBodyData)

	TraceLogger.Println("Where:", "after r.Body copy back")

	// DEBUG incoming request
	TraceLogger.Printf("INCOMING REQUEST: Method=%s, URL=%s, Proto=%s, Host=%s, TLS=%v",
		r.Method, r.URL.String(), r.Proto, r.Host, r.TLS != nil)

	// always replace r.Host with configured AwsDomain
	innerRequest := &http.Request{
		Method:           r.Method,
		URL:              r.URL,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		Header:           r.Header.Clone(),
		Body:             r.Body,
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Host:             h.config.Server.AwsDomain,
		Form:             r.Form,
		PostForm:         r.PostForm,
		MultipartForm:    r.MultipartForm,
		Trailer:          r.Trailer,
	}

	innerRequest.URL.Host = h.config.Server.AwsDomain
	innerRequest.Header.Set("Host", h.config.Server.AwsDomain)

	// convert virtual host style to path style for external requests to s3
	if info != nil && info.VirtualHost && info.Name != "" {
		if innerRequest.URL.Path == "/" || innerRequest.URL.Path == "" {
			innerRequest.URL.Path = "/" + info.Name + "/"
			InfoLogger.Printf("Virtual host to path style: / -> /%s/", info.Name)
		} else if !strings.HasPrefix(innerRequest.URL.Path, "/"+info.Name) {
			innerRequest.URL.Path = "/" + info.Name + innerRequest.URL.Path
			InfoLogger.Printf("Virtual host to path style: %s -> %s", r.URL.Path, innerRequest.URL.Path)
		}
	}

	TraceLogger.Println("Where:", "before innerRequest.URL.Scheme")

	if info == nil {
		// use https if bucket non defined (list for example)
		innerRequest.URL.Scheme = "https"
		TraceLogger.Printf("Using default HTTPS scheme for request without bucket")
	} else if info.Config == nil {
		// use https if bucket defined but not in config file
		innerRequest.URL.Scheme = "https"
		TraceLogger.Printf("Using default HTTPS scheme for unconfigured bucket: %s", info.Name)
	} else {
		// use schema if configured for bucket
		innerRequest.URL.Scheme = info.Config.Protocol
		TraceLogger.Printf("Using configured scheme %s for bucket: %s", info.Config.Protocol, info.Name)
	}

	// DEBUG outgoing request
	TraceLogger.Printf("OUTGOING TO S3: URL=%s, Scheme=%s, Host=%s",
		innerRequest.URL.String(), innerRequest.URL.Scheme, innerRequest.Host)

	if innerRequest.URL.Host != h.config.Server.AwsDomain {
		ErrorLogger.Printf("URL HOST MISMATCH: expected=%s, actual=%s",
			h.config.Server.AwsDomain, innerRequest.URL.Host)
	}

	TraceLogger.Println("Where:", "after innerRequest.URL.Scheme")

	var originalBodyHash *CountingHash

	// we need to encrypt and replace md5 hashes in case of PUT requests
	dataCheckNeeded := r.Method == "PUT" && info != nil && info.Config != nil

	if dataCheckNeeded {
		originalBodyHash = NewCountingHash(md5.New())
		teereader := io.TeeReader(r.Body, originalBodyHash)
		r.Body = io.NopCloser(teereader)
	}

	TraceLogger.Println("Where:", "after originalBodyHash constructing")

	// encrypt Body if enabled in config file
	innerBodyHash, err := h.PreRequestEncryptionHook(r, innerRequest, info)

	TraceLogger.Println("Where:", "after PreRequestEncryptionHook")

	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Error while setting up encryption: %s", err)
		return
	}

	var innerRequestBodyData bytes.Buffer

	// check encryption needed
	if info != nil && info.Config != nil && info.Config.EncryptionKey != "" {
		// encryption enabled for bucket
		copyRequest := innerRequest.Header.Get("x-amz-copy-source")
		if copyRequest == "" {
			TraceLogger.Println("Where:", "before io.CopyBuffer(&innerRequestBodyData, ...")
			buf := make([]byte, 1<<20) // 1MB buffer
			_, err := io.CopyBuffer(&innerRequestBodyData, innerRequest.Body, buf)
			if err != nil {
				failRequest(w, http.StatusInternalServerError, "Error while copying request body: %s", err)
				return
			}
			TraceLogger.Println("Where:", "after io.CopyBuffer(&innerRequestBodyData, ...")

			innerRequest.Body = io.NopCloser(bytes.NewBuffer(innerRequestBodyData.Bytes()))
		}
		TraceLogger.Println("Where:", "before h.SignRequestV4(innerRequestBodyData)")
		err = h.SignRequestV4(innerRequest, info, innerRequestBodyData.Bytes())
	} else {
		// no encryption enabled or bucket is not configured
		TraceLogger.Println("Where:", "before h.SignRequestV4(originalBodyData)")
		err = h.SignRequestV4(innerRequest, info, originalBodyData.Bytes())
	}

	TraceLogger.Println("Where:", "after h.SignRequestV4")

	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Error while signing the request: %s", err)
		return
	}

	// retries for failed requests
	maxRetryCount := 0
	retryCount := 0
	retryDelay := 0

	if info != nil && info.Config != nil {
		maxRetryCount = info.Config.RetryCount
		retryDelay = info.Config.RetryDelay
	}

	var innerResponse *http.Response

	for {
		TraceLogger.Println("Where:", "before h.client.Do(innerRequest)")
		// send request to s3 server
		// debug before sending request
		TraceLogger.Printf("BEFORE client.Do: URL=%s, Method=%s",
			innerRequest.URL.String(), innerRequest.Method)

		// DEBUG innerRequest before send
		TraceLogger.Printf("INNER REQUEST BEFORE SEND:")
		TraceLogger.Printf("  Method: %s", innerRequest.Method)
		TraceLogger.Printf("  URL: %s", innerRequest.URL.String())
		TraceLogger.Printf("  Content-Length: %d", innerRequest.ContentLength)

		// all headers
		TraceLogger.Printf("  Headers:")
		for k, v := range innerRequest.Header {
			TraceLogger.Printf("    %s: %v", k, v)
		}

		// body
		if innerRequest.Body != nil {
			bodyBytes, err := io.ReadAll(innerRequest.Body)
			if err != nil {
				TraceLogger.Printf("  Body: [error reading: %v]", err)
				innerRequest.Body = io.NopCloser(bytes.NewBuffer(nil))
			} else {
				bodyStr := string(bodyBytes)
				if len(bodyStr) > 4096 {
					bodyStr = bodyStr[:4096] + "... [truncated]"
				}
				TraceLogger.Printf("  Body (%d bytes): %s", len(bodyBytes), bodyStr)
				innerRequest.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		innerResponse, err = h.client.Do(innerRequest)

		// check response
		if err != nil {
			InfoLogger.Printf("ERROR IN client.Do: %v", err)
			if urlErr, ok := err.(*url.Error); ok {
				InfoLogger.Printf("URL ERROR: Op=%s, URL=%s", urlErr.Op, urlErr.URL)
			}
		}

		TraceLogger.Println("Where:", "AFTER h.client.Do(innerRequest)")

		// DEBUG inner response from s3 server
		TraceLogger.Printf("INNER RESPONSE: err=%v", err)
		if innerResponse.Body != nil {
			bodyBytes, err := io.ReadAll(innerResponse.Body)
			if err != nil {
				TraceLogger.Printf("  Body: [error reading: %v]", err)
				innerResponse.Body = io.NopCloser(bytes.NewBuffer(nil))
			} else {
				bodyStr := string(bodyBytes)
				if len(bodyStr) > 4096 {
					bodyStr = bodyStr[:4096] + "... [truncated]"
				}
				TraceLogger.Printf("  Body (%d bytes): %s", len(bodyBytes), bodyStr)
				innerResponse.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		} else {
			TraceLogger.Printf("  Response: NIL")
		}

		if err != nil {
			failRequest(w, http.StatusInternalServerError, "Error while serving the request: %s", err)
			return
		}

		defer func() {
			if innerResponse != nil && innerResponse.Body != nil {
				if closeErr := innerResponse.Body.Close(); closeErr != nil {
					ErrorLogger.Printf("Error closing inner response body: %v", closeErr)
				}
			}
		}()

		if err == nil && innerResponse.StatusCode < 300 {
			break
		}

		requestFailed := (err != nil || innerResponse.StatusCode >= http.StatusInternalServerError)

		if retryCount < maxRetryCount && requestFailed {
			InfoLogger.Printf("Request to %s failed, retrying after %d ms (try %d out of %d)", innerRequest.URL, retryDelay, 1+retryCount, 1+maxRetryCount)

			retryCount++
			time.Sleep(time.Duration(retryDelay) * time.Millisecond)
			continue
		}

		if err != nil {
			failRequest(w, http.StatusInternalServerError, "Error while serving the request: %s", err)
			return
		}

		// We had a 5xx response, but no error from the HTTP client: just
		// forward the response, that will get to the client

		// Do not try to update the metadata if the request failed
		dataCheckNeeded = false

		break
	}

	if dataCheckNeeded {
		originalEtag := fmt.Sprintf("\"%x\"", originalBodyHashStatic.Sum(nil)) // md5 of original client request

		// always return originalEtag (for encrypted and non encrypted requests)
		innerResponse.Header["Etag"] = []string{originalEtag}

		// Let's also store the original metadata in S3, so we can use it later
		// for HEAD and GET requests (if we uploaded any data). We encrypt the
		// metadata too.

		if innerBodyHash != nil {
			// if we are here, then PUT request was used and encryption was enabled
			// we need to save original md5 in s3 metadata for returning it to client
			metadata := &ObjectMetadata{
				originalBodyHashStatic.Count(),
				originalEtag,
			}

			err = h.UpdateObjectMetadata(innerRequest.URL, metadata, r.Header, info)

			if err != nil {
				failRequest(w, http.StatusInternalServerError, "Error while updating metadata: %s", err)
				return
			}
		}
	}

	// response generation function with decryption (if enabled)
	responseReader, err := h.PostRequestEncryptionHook(r, innerResponse, info)

	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Error while setting up decryption: %s", err)
		return
	}

	for k, vs := range innerResponse.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(innerResponse.StatusCode)
	_, err = io.Copy(w, responseReader)
	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Error while copying response body: %s", err)
		return
	}

	TraceLogger.Println("Where:", "end of ServeHTTP")
	printMemStats()
}

func NewProxyHandler(config *Config) *ProxyHandler {
	tlsConfig := &tls.Config{}

	// disable TLS check if InsecureTLS is enabled
	if config.Server.InsecureTLS {
		tlsConfig.InsecureSkipVerify = true
		InfoLogger.Printf("TLS certificate verification is DISABLED (InsecureTLS=true)")
	} else {
		InfoLogger.Printf("TLS certificate verification is enabled")
	}

	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: config.Server.DisableKeepAlives,
		TLSClientConfig:   tlsConfig,
	}

	return &ProxyHandler{
		config:          config,
		client:          &http.Client{Transport: transport},
		credentialCache: NewCredentialCache(),
	}
}

func main() {
	startPprofServer() // start profiling server
	// set flags if -debug=XXX was used
	var debugLevel = flag.String("debug", "false", "trace")

	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	enableDebugMode(*debugLevel)

	InfoLogger.Printf("Enabling debug messages (debug=%s). Version %s", *debugLevel, CurrentVersion)

	// read configuration file
	config, err := parseConfig(flag.Args()[0])

	if err != nil {
		ErrorLogger.Printf("Error while parsing the configuration file: %s\n", err)
		os.Exit(1)
	}

	// start server and waiting for incoming requests
	handler := NewProxyHandler(config)

	listenAddress := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)

	InfoLogger.Printf("Use AwsDomain=%s\n", handler.config.Server.AwsDomain)

	if err := http.ListenAndServe(listenAddress, handler); err != nil {
		ErrorLogger.Fatalf("Failed to start s3 proxy server: %v", err)
	}

}
