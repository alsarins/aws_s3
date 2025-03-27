package main

import (
	"bytes"
	"crypto/md5"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var CurrentVersion string = "1.0.13"

func printMemStats() {
	TraceLogger.Println("Where:", "printMemStats")
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	TraceLogger.Printf("Alloc = %v MiB, TotalAlloc = %v MiB, Sys = %v MiB, NumGC = %v\n", m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}

func startPprofServer() {
	/* Запускаем HTTP-сервер на localhost:6060 для сбора данных PPROF
	можно через браузер смотреть, можно через консоль анализировать (удобнее):

	curl -o /tmp/mem.pprof http://localhost:6060/debug/pprof/heap
	go tool pprof /tmp/mem.pprof

	top — показать топ потребителей памяти.
	list <функция> — показать распределение памяти по конкретной функции.
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

	// Список параметров, которые нужно проверить
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
	portIdx := strings.IndexRune(r.Host, ':')

	if portIdx == -1 {
		portIdx = len(r.Host)
	}

	host := r.Host[0:portIdx]

	if !strings.HasSuffix(host, h.config.Server.AwsDomain) {
		InfoLogger.Println("Non Amazon domain specified")
		return nil
	}

	fmt.Println("main.go 3")
	var bucketName string
	// Whether the URL was using  bucket.s3.amazonaws.com instead of s3.amazonaws.com/bucket/
	bucketVirtualHost := false

	if len(host) > len(h.config.Server.AwsDomain) {
		bucketName = host[0 : len(host)-len(h.config.Server.AwsDomain)-1]
		bucketVirtualHost = true
	} else {
		tokens := strings.Split(r.URL.Path, "/")

		// Split produces empty tokens which we are not interested in
		for _, t := range tokens {
			if t == "" {
				continue
			}

			bucketName = t
			break
		}
	}

	TraceLogger.Println("Where:", "end GetBucketInfo")
	return &BucketInfo{
		Name:        bucketName,
		VirtualHost: bucketVirtualHost,
		Config:      h.config.Buckets[bucketName],
	}
}

func (h *ProxyHandler) PreRequestEncryptionHook(r *http.Request, innerRequest *http.Request, info *BucketInfo) (*CountingHash, error) {
	TraceLogger.Println("Where:", "PreRequestEncryptionHook")
	// если это не PUT запрос или не задан info.Config.EncryptionKey то не требуется шифрование
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" || r.Method != "PUT" {
		return nil, nil
	}

	// если мы здесь, значит задано шифрование PUT запроса

	// если у нас есть заголовок x-amz-copy-source, то мы делаем PUT запрос обновления метаданных
	// он не содержит Body, в нем только заголовки, шифрование не требуется
	//  цикл только по ключам, значения нам не нужны
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-copy-source") {
			return nil, nil
		}
	}

	// шифруем тело запроса здесь
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
	// для PUT запросов у нас нет тела ответа, там должны вернуться только корректный StatusCode и заголовки типа Etag
	// для GET запросов у нас должно возвращаться дешифрованное Body содержимого файла

	// копируем Body ответа
	// innerResponseBodyData, err := io.ReadAll(innerResponse.Body)
	// innerResponse.Body = io.NopCloser(bytes.NewBuffer(innerResponseBodyData))

	// если не используется шифрование, возвращаем исходное тело запроса
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" {
		return innerResponse.Body, nil
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		// для PUT и POST запросов возвращаем исходное тело запроса
		return innerResponse.Body, nil
	}

	if innerResponse.StatusCode >= 300 {
		return innerResponse.Body, nil
	}

	// When listing folders, the returned data is not going to be encrypted
	if strings.HasSuffix(r.URL.Path, "/") {
		InfoLogger.Print("Directory listing request, skipping decryption")
		return innerResponse.Body, nil
	}

	// TODO: здесь нужно добавить проверку на метаданные. Если в метаданных есть данные для дешифрации, только тогда запускать дешифрацию.
	// Иначе следующие шаги вместо валидной дешифрации возвращают мусор

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

	// копируем Body ответа
	// innerResponseBodyData, err = io.ReadAll(innerResponse.Body)
	// innerResponse.Body = io.NopCloser(bytes.NewBuffer(innerResponseBodyData))

	if r.Method == "HEAD" {
		return innerResponse.Body, nil
	}

	decryptedReader, minuslen, err := SetupReadEncryption(innerResponse.Body, info)

	if err != nil {
		return nil, err
	}

	defer decryptedReader.Close()

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
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html

	// если у нас нет инфо о бакете, то выходим. Это может быть в случае запроса отличного от GET/PUT/POST, такие мы не обрабатываем
	if info == nil || info.Config == nil {
		return nil
	}

	// TODO: Нужно сделать bodyData необязательным параметром
	// если нам не передали bodyData, то вычитываем его из request.
	// Это может быть в случае запроса на обновление метаданных

	// check if we have credentials configured
	credentials, err := h.GetBucketSecurityCredentials(info.Config)
	if err != nil {
		return err
	}

	region := info.Config.Region
	service := "s3" // should not be changed

	TraceLogger.Println("Where:", "SignRequestV4 1")
	// формируем заголовки для канонического запроса.
	// сначала убираем ненужные
	headers_to_ignore := []string{"authorization", "connection", "x-amzn-trace-id", "user-agent", "expect", "presigned-expires", "range", "proxy-connection", "accept-encoding"}

	for _, header_to_remove := range headers_to_ignore {
		r.Header.Del(header_to_remove)
	}

	TraceLogger.Println("Where:", "before adding headers")
	// проверяем и добавляем нужные
	content_type := r.Header.Get("Content-Type")
	content_length := r.Header.Get("Content-Length")

	TraceLogger.Println("Where:", "before adding Content-Type, Content-Length, Content-Md5")
	// добавляем Content-Type, Content-Length, Content-Md5 для POST запросов, если их нет. Для других - вроде необязательно
	if r.Method == "POST" {
		if content_type == "" {
			content_type = "text/plain" // Считаем, что нам должен прийти просто текст. Если будет octet-stream то могут быть проблемы. TODO: добавить проверок, при необходимости перейти на []byte
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

	// добавить Date и/или X-Amz-Date header. Что-то из двух точно должно быть, могут быть сразу оба, тогда приоритет у Date
	amazonDate := r.Header.Get("Date")
	if amazonDate == "" && r.Header.Get("x-amz-date") == "" {
		amazonDate = time.Now().UTC().Format("20060102T150405Z")
		r.Header.Set("Date", amazonDate)
	}

	TraceLogger.Println("Where:", "before X-Amz-Content-Sha256")
	// Добавить заголовок X-Amz-Content-Sha256
	r.Header.Set("X-Amz-Content-Sha256", calculateSHA256Optimized(bodyData))
	TraceLogger.Println("Where:", "after X-Amz-Content-Sha256")

	// x-amz-security-token - не знаю что это, но тоже пусть будет
	if credentials.Token != "" {
		r.Header.Add("x-amz-security-token", credentials.Token)
	}

	// Добавляем все остальные x-amz-* заголовки
	canonicalizedAmzHeaders := bytes.NewBuffer(nil)
	amzHeaders := []string{}

	//  цикл только по ключам, значения нам не нужны
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

	// добавляем в заголовок Host
	r.Header.Set("Host", r.URL.Host)

	TraceLogger.Println("Where:", "before createCanonicalRequestV4")
	// Шаг 1: создаем канонический запрос
	canonicalRequest := createCanonicalRequestV4(r, bodyData)

	// DEBUG
	// TraceLogger.Printf("Canonical Request:\n%s\n", canonicalRequest)
	// TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before createStringToSignV4")
	// Шаг 2: Создать строку для подписи
	stringToSign := createStringToSignV4(r, canonicalRequest, region, service)

	// DEBUG
	// TraceLogger.Printf("StringToSign:\n%s\n", stringToSign)
	// TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before getSigningKey")
	// Шаг 3: Вычисляем ключ для подписи
	signingKey := getSigningKey(credentials.SecretAccessKey, r.Header.Get("X-Amz-Date")[:8], region, service)

	// DEBUG
	// TraceLogger.Printf("signingKey:%s\n", hex.EncodeToString(signingKey))
	// TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before calculateSignatureV4")
	// Шаг 5: Вычисляем подпись на основе ключа и строки для подписи
	signature_v4 := calculateSignatureV4(signingKey, stringToSign)

	// DEBUG
	// TraceLogger.Printf("signature:%s\n", signature_v4)
	// TraceLogger.Println("----------------------------------------------")

	TraceLogger.Println("Where:", "before Authorization header")
	// Добавляем подпись в заголовок Authorization
	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
		credentials.AccessKeyId,
		r.Header.Get("X-Amz-Date")[:8],
		region,
		service,
		createSignedHeadersV4(r.Header),
		signature_v4,
	))

	TraceLogger.Println("Where:", "end SignRequestV4")
	return nil
}

// старый (оригинальный) механизм подписи V2. TODO: сделать опциональным или выкинуть совсем
// Тут как минимум неправильно формируется канонический запрос для POST
//func (h *ProxyHandler) SignRequest(r *http.Request, info *BucketInfo) error {
//	// See http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader

//	if info == nil || info.Config == nil {
//		return nil
//	}
//	credentials, err := h.GetBucketSecurityCredentials(info.Config)

//	if err != nil {
//		return err
//	}

//	dateStr := r.Header.Get("Date")

//	if dateStr == "" && r.Header.Get("x-amz-date") == "" {
//		dateStr = time.Now().UTC().Format(time.RFC1123Z)
//		r.Header.Set("Date", dateStr)
//	}

//	if credentials.Token != "" {
//		r.Header.Add("x-amz-security-token", credentials.Token)
//	}

//	canonicalizedResource := bytes.NewBuffer(nil)

//	if info.VirtualHost {
//		canonicalizedResource.WriteString("/" + info.Name)
//	}

//	if r.Method == "POST" {
//		canonicalizedResource.WriteString(r.URL.Path + "?" + r.URL.RawQuery)
//	} else {
//		canonicalizedResource.WriteString(r.URL.Path)
//	}

//	canonicalizedAmzHeaders := bytes.NewBuffer(nil)

//	amzHeaders := []string{}

//	for k, _ := range r.Header {
//		if !strings.HasPrefix(strings.ToLower(k), "x-amz-") {
//			continue
//		}

//		amzHeaders = append(amzHeaders, k)
//	}

//	sort.Strings(amzHeaders)

//	for _, k := range amzHeaders {
//		canonicalizedAmzHeaders.WriteString(strings.ToLower(k))
//		canonicalizedAmzHeaders.WriteString(":")
//		canonicalizedAmzHeaders.WriteString(strings.Join(r.Header[k], ","))
//		canonicalizedAmzHeaders.WriteString("\n")
//	}

//	buf := bytes.NewBuffer(nil)

//	buf.WriteString(r.Method)
//	buf.WriteString("\n")

//	buf.WriteString(r.Header.Get("Content-MD5"))
//	buf.WriteString("\n")

//	buf.WriteString(r.Header.Get("Content-Type"))
//	buf.WriteString("\n")

//	buf.WriteString(dateStr)
//	buf.WriteString("\n")

//	if r.Method != "POST" {
//		buf.WriteString(canonicalizedAmzHeaders.String())
//	}
//	buf.WriteString(canonicalizedResource.String())

//	signature := hmac.New(sha1.New, ([]byte)(credentials.SecretAccessKey)) // это хэш SecretKey которым будем подписывать содержимое запроса
//	signature.Write(buf.Bytes()) // это мы подписываем нашим SecretKey содержимое канонического запроса

//	signature64 := bytes.NewBuffer(nil)

//	b64encoder := base64.NewEncoder(base64.StdEncoding, signature64)
//	b64encoder.Write(signature.Sum(nil))
//	b64encoder.Close()

//	signatureHdr := fmt.Sprintf("AWS %s:%s", credentials.AccessKeyId, signature64.String())

//	r.Header.Set("Authorization", signatureHdr)

//	InfoLogger.Printf("Signed request (signature: %s )", signatureHdr)

//	return nil
//}

func connectResponseOK(w http.ResponseWriter, format string, args ...interface{}) {
	// отвечаем 200 если к нам пришел запрос CONNECT (для https прокси и прокси с авторизацией)
	// саму авторизацию мы не реализуем
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, format, args...)
	InfoLogger.Printf(format, args...)
}

func failRequest(w http.ResponseWriter, statusCode int, format string, args ...interface{}) {
	const ErrorFooter = "\n\nGreetings, the S3Proxy\n"

	w.WriteHeader(statusCode) // Используем переданный статус
	fmt.Fprintf(w, format+ErrorFooter, args...)
	ErrorLogger.Printf(format, args...)
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// выводим состояние памяти
	TraceLogger.Println("Where:", "start ServeHTTP")
	printMemStats()

	// // Фиксируем состояние памяти до обработки запроса
	// f, err := os.Create("/tmp/heap_before.pprof")
	// if err != nil {
	// 	log.Fatal("Could not create memory profile: ", err)
	// }
	// defer f.Close()
	// pprof.WriteHeapProfile(f)

	// основная функция, обеспечивающая обработку входящих запросов
	InfoLogger.Printf("%s %s (Host: %s)", r.Method, r.URL, r.Host)

	// если пришел CONNECT, то надо ответить 200 OK и все
	if r.Method == "CONNECT" {
		connectResponseOK(w, "Connection Established")
		return
	}

	if IsMultipartRequest(r) && (r.Method == "PUT" || r.Method == "POST") {
		fmt.Println("IsMultipartRequest = true. end with http.StatusNotImplemented")
		failRequest(w, http.StatusNotImplemented, "Multiparts are not supported: %s", r.Method)
		return
	}

	// читаем конфигурацию для бакета
	info := h.GetBucketInfo(r)

	if info == nil {
		InfoLogger.Print("Not an S3 request")
	} else {
		if info.Config == nil {
			InfoLogger.Printf("No configuration for S3 bucket %s", info.Name)
		} else {
			InfoLogger.Printf("Handling request for bucket %s", info.Name)
		}
	}

	// TraceLogger.Println("Where:", "before originalBodyData")
	// printMemStats()

	defer r.Body.Close() // Закрываем тело запроса принудительно в случае сбоя

	// Создаем буфер для хранения оригинального тела запроса
	var originalBodyData bytes.Buffer
	originalBodyHashStatic := NewCountingHash(md5.New())
	// Копируем данные из r.Body в originalBodyData и originalBodyHashStatic
	// INFO: тяжелая операция, зависит от размера пакета:
	TraceLogger.Println("Where:", "before originalBodyData copy")
	teereader := io.TeeReader(r.Body, io.MultiWriter(&originalBodyData, originalBodyHashStatic))
	buf := make([]byte, 1<<20) // 1MB буфер
	_, err := io.CopyBuffer(io.Discard, teereader, buf)
	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Failed to read original request body: %s", err)
		return
	}
	// _, _ = io.Copy(io.Discard, teereader)		// original copy
	TraceLogger.Println("Where:", "after originalBodyData copy")

	// Восстанавливаем r.Body для дальнейшего использования
	r.Body = io.NopCloser(&originalBodyData)

	// // Делаем копию r.Body оригинального запроса (так как объект io.ReadCloser обнуляется после вычитывания)
	// originalBodyData, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	failRequest(w, http.StatusInternalServerError, "Failed to read request body: %s", err)
	// 	return
	// }

	// printMemStats()

	// Восстанавливаем r.Body для дальнейшего использования
	// r.Body = io.NopCloser(bytes.NewBuffer(originalBodyData))

	TraceLogger.Println("Where:", "after r.Body copy back")
	// printMemStats()

	// TODO: кажется тут можно оптимизировать, нам из всего запроса по факту нужно только Body
	// копируем http request для рассчета оригинального md5 для PUT запроса
	// Создаем новый запрос с теми же параметрами
	// reqCopy := &http.Request{
	// 	Method:           r.Method,
	// 	URL:              &(*r.URL), // Копируем URL
	// 	Proto:            r.Proto,
	// 	ProtoMajor:       r.ProtoMajor,
	// 	ProtoMinor:       r.ProtoMinor,
	// 	Header:           make(http.Header),                                   // Копируем заголовки
	// 	Body:             io.NopCloser(bytes.NewBuffer(originalBodyData)), // Копируем тело
	// 	ContentLength:    r.ContentLength,
	// 	TransferEncoding: r.TransferEncoding,
	// 	Close:            r.Close,
	// 	Host:             r.Host,
	// 	Form:             r.Form,
	// 	PostForm:         r.PostForm,
	// 	MultipartForm:    r.MultipartForm,
	// 	Trailer:          r.Trailer,
	// }

	// Копируем заголовки (вообще они не нужны, но могут пригодиться для дебага)
	// for key, values := range r.Header {
	// 	for _, value := range values {
	// 		reqCopy.Header.Add(key, value)
	// 	}
	// }

	// создаем статический хэш для тела запроса, потому что io.TeeReader его меняет по мере вычитывания данных
	// var originalBodyHashStatic *CountingHash

	// вычисляем статический хэш на основе копии тела запроса
	// originalBodyHashStatic = NewCountingHash(md5.New())

	// TraceLogger.Println("Where:", "after originalBodyHashStatic md5 counting")
	// printMemStats()

	// _, _ = io.Copy(originalBodyHashStatic, r.Body)
	// r.Body = io.NopCloser(bytes.NewBuffer(originalBodyData))

	// TraceLogger.Println("Where:", "after r.Body copy back originalBodyData")
	// printMemStats()

	innerRequest := &http.Request{
		Method:           r.Method,
		URL:              r.URL,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		Header:           r.Header,
		Body:             r.Body,
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Host:             r.Host,
		Form:             r.Form,
		PostForm:         r.PostForm,
		MultipartForm:    r.MultipartForm,
		Trailer:          r.Trailer,
	}

	TraceLogger.Println("Where:", "before innerRequest.URL.Scheme")
	if info.Config == nil {
		innerRequest.URL.Scheme = "https" // fallback to https if no bucket specified, or non s3 request
	} else {
		innerRequest.URL.Scheme = info.Config.Protocol
	}

	TraceLogger.Println("Where:", "after innerRequest.URL.Scheme")

	innerRequest.URL.Host = r.Host

	TraceLogger.Println("Where:", "after innerRequest constructing")
	// printMemStats()

	var originalBodyHash *CountingHash

	// нам нужно шифровать и заменять md5 хэши в случае PUT запросов
	dataCheckNeeded := r.Method == "PUT" && info != nil

	if dataCheckNeeded {
		originalBodyHash = NewCountingHash(md5.New())
		teereader := io.TeeReader(r.Body, originalBodyHash)
		r.Body = io.NopCloser(teereader)
	}

	TraceLogger.Println("Where:", "after originalBodyHash constructing")
	// printMemStats()

	// шифруем Body и получаем хэш шифрованного запроса (если оно включено в конфиге)
	// innerBodyHash динамически меняется
	innerBodyHash, err := h.PreRequestEncryptionHook(r, innerRequest, info)

	TraceLogger.Println("Where:", "after PreRequestEncryptionHook")
	// printMemStats()

	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Error while setting up encryption: %s", err)
		return
	}

	var innerRequestBodyData bytes.Buffer

	if info.Config != nil && info.Config.EncryptionKey != "" {
		// мы должны передавать на подпись шифрованное тело запроса, вместо оригинального при включенном шифровании
		copyRequest := innerRequest.Header.Get("x-amz-copy-source")
		if copyRequest == "" {
			// это не PUT запрос для обновления метаданных (у него пустой Body) и включено шифрование, значит берем Body после шифрования
			// Внимание, здесь мы читаем шифрованное тело в переменную, увеличивая занятую память на размер тела пакета
			// innerRequestBodyData, err = io.ReadAll(innerRequest.Body)
			// INFO: тяжелая операция, зависит от размера пакета
			TraceLogger.Println("Where:", "before io.CopyBuffer(&innerRequestBodyData, ...")
			// _, err := io.Copy(&innerRequestBodyData, innerRequest.Body)		// original copy
			buf := make([]byte, 1<<20) // 1MB буфер
			_, err := io.CopyBuffer(&innerRequestBodyData, innerRequest.Body, buf)
			if err != nil {
				failRequest(w, http.StatusInternalServerError, "Error while copying request body: %s", err)
				return
			}
			TraceLogger.Println("Where:", "after io.CopyBuffer(&innerRequestBodyData, ...")

			// Сохраняем тело запроса в файл
			// err = os.WriteFile("/tmp/debug_request_body.file", innerRequestBodyData, 0644)
			// if err != nil {
			// 	failRequest(w, http.StatusInternalServerError, "Error while saving request body to file: %s", err)
			// 	return
			// }

			innerRequest.Body = io.NopCloser(bytes.NewBuffer(innerRequestBodyData.Bytes()))
		}
		TraceLogger.Println("Where:", "before h.SignRequestV4(innerRequestBodyData)")
		// printMemStats()
		err = h.SignRequestV4(innerRequest, info, innerRequestBodyData.Bytes())
	} else {
		// если шифрование не включено, отдаем на подпись оригинальное тело запроса
		TraceLogger.Println("Where:", "before h.SignRequestV4(originalBodyData)")
		// printMemStats()
		err = h.SignRequestV4(innerRequest, info, originalBodyData.Bytes())
	}

	TraceLogger.Println("Where:", "after h.SignRequestV4")
	// printMemStats()

	// defer func() {
	// 	originalBodyData = nil // Освобождаем ссылку на данные, если на переменную нет больше ссылок. Ускоряем garbage collector
	// }()

	if err != nil {
		failRequest(w, http.StatusInternalServerError, "Error while signing the request: %s", err)
		return
	}

	// в случае если запрос зафейлится пробуем столько ретраев и с такими интервалами, какие заданы в конфиге
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
		// посылаем запрос на сервер и получаем ответ
		innerResponse, err = h.client.Do(innerRequest)
		TraceLogger.Println("Where:", "after h.client.Do(innerRequest)")

		if err != nil {
			failRequest(w, http.StatusInternalServerError, "Error while serving the request: %s", err)
			return
		}

		defer func() {
			if innerResponse != nil && innerResponse.Body != nil {
				innerResponse.Body.Close()
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
		// если мы здесь, значит обрабатываем PUT запрос
		// awsEtag := innerResponse.Header.Get("Etag") // оригинальный md5 ОТВЕТА от сервера (после отправки шифрованного или нешифрованного запроса)

		// это оригинальный md5 и Etag шифрованного (либо нешифрованного) ЗАПРОСА
		// bodyHash := innerBodyHash

		// if bodyHash == nil {
		// 	// если мы здесь, значит либо шифрование не использовалось, либо это x-amz-copy-source (когда мы обновляем только метаданные)
		// 	// См. PreRequestEncryptionHook
		// 	bodyHash = originalBodyHash
		// } else {
		// 	// если же шифрование использовалось, то берем md5 первоначального (нешифрованного) запроса
		// 	bodyHash = originalBodyHashStatic
		// }

		// innerEtag := fmt.Sprintf("\"%x\"", bodyHash.Sum(nil))		// это md5 нешифрованного запроса, который подготовил наш прокси

		originalEtag := fmt.Sprintf("\"%x\"", originalBodyHashStatic.Sum(nil)) // это md5 оригинального запроса с клиента

		// возвращаем всегда originalEtag. Это должно работать и для шифрованных и нешифрованных запросов
		innerResponse.Header["Etag"] = []string{originalEtag}

		// Let's also store the original metadata in S3, so we can use it later
		// for HEAD and GET requests (if we uploaded any data). We encrypt the
		// metadata too.

		if innerBodyHash != nil {
			// если мы здесь, значит при PUT запросе использовалось шифрование
			// нам нужно сохранить в s3 метаданных md5 оригинального запроса для последующих возвратов клиенту
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

	// функция возврата ответа и дешифрации при необходимости
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
	// // Фиксируем состояние памяти после обработки запросов
	// f2, err := os.Create("/tmp/heap_after.pprof")
	// if err != nil {
	// 	log.Fatal("Could not create memory profile: ", err)
	// }
	// defer f2.Close()
	// pprof.WriteHeapProfile(f2)
}

func NewProxyHandler(config *Config) *ProxyHandler {
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: config.Server.DisableKeepAlives,
	}

	return &ProxyHandler{
		config:          config,
		client:          &http.Client{Transport: transport},
		credentialCache: NewCredentialCache(),
	}
}

// benchmarkFunction запускает функцию несколько раз и возвращает среднее время выполнения
// func benchmarkFunction(name string, fn func(string) string, data string, iterations int) {
// 	var totalDuration time.Duration

// 	for i := 0; i < iterations; i++ {
// 		start := time.Now()
// 		fn(data) // Выполняем функцию
// 		duration := time.Since(start)
// 		totalDuration += duration
// 	}

// 	avgDuration := totalDuration / time.Duration(iterations)
// 	fmt.Printf("%s: Среднее время выполнения за %d итераций: %v\n", name, iterations, avgDuration)
// }

func main() {
	startPprofServer() // Запускаем сервер pprof
	// если приложение запущено с флагом командной строки -debug=XXX то выводим доп информацию в stdout
	var debugLevel = flag.String("debug", "false", "trace")

	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	enableDebugMode(*debugLevel)

	// если включено логирование, то сообщаем об этом
	InfoLogger.Printf("Enabling debug messages (debug=%s). Version %s", *debugLevel, CurrentVersion)

	// читаем конфигурационный файл, запускаем слушающий процесс, ждем запросов на обработку
	config, err := parseConfig(flag.Args()[0])

	if err != nil {
		ErrorLogger.Printf("Error while parsing the configuration file: %s\n", err)
		os.Exit(1)
	}

	handler := NewProxyHandler(config)

	listenAddress := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)

	InfoLogger.Printf("Use AwsDomain=%s\n", handler.config.Server.AwsDomain)

	// http.ListenAndServe(listenAddress, handler)
	if err := http.ListenAndServe(listenAddress, handler); err != nil {
		ErrorLogger.Fatalf("Failed to start s3 proxy server: %v", err)
	}

}
