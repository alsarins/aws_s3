package main

import (
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

func calculateMD5Optimized(data string) string {
	hash := md5.New()
	reader := strings.NewReader(data)
	buf := make([]byte, 32*1024) // 32KB буфер

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

func calculateSHA256(data string) string {
	// калькуляция sha256 хэша в hex формате
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// func calculateMD5(data string) string {
// 	// калькуляция md5 хэша в hex формате
// 	hash := md5.Sum([]byte(data))
// 	return base64.StdEncoding.EncodeToString(hash[:])
// }

func createSignedHeadersV4(headers http.Header) string {
	// создание списка подписанных заголовков. Должны быть в lowercase, отсортированы по алфавиту, через ";"
	var signedHeaders []string
	for key := range headers {
		signedHeaders = append(signedHeaders, strings.ToLower(key))
	}
	sort.Strings(signedHeaders)
	return strings.Join(signedHeaders, ";")
}

func createCanonicalHeadersV4(headers http.Header) string {
	// создание канонических заголовков. Должны быть в lowercase и отсортированы по алфавиту, через ","
	var canonicalHeaders []string
	for key, values := range headers {
		canonicalHeaders = append(canonicalHeaders, fmt.Sprintf("%s:%s", strings.ToLower(key), strings.Join(values, ",")))
	}
	sort.Strings(canonicalHeaders)
	return strings.Join(canonicalHeaders, "\n") + "\n"
}

func createCanonicalRequestV4(r *http.Request, payload string) string {
	// создание канонического запроса
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-canonical-request

	method := r.Method

	// canonicalURI - все, что после имени домена и до параметров (символа ?) или конца URL
	canonicalURI := r.URL.Path

	// canonicalQuery - разобранные параметры запроса (после символа ? в URL)
	var canonicalQuery string = ""

	// разбираем параметры запроса, если они есть и формируем canonicalQuery
	req_params, _ := url.ParseQuery(r.URL.RawQuery)
	var paramStrings []string
	for key, values := range req_params {
		if len(values) == 0 {
			// Если значение отсутствует, добавляем ключ с пустым значением в нижнем регистре
			paramStrings = append(paramStrings, fmt.Sprintf("%s=", url.QueryEscape(strings.ToLower(key))))
		} else {
			// Если есть значения, добавляем каждое значение с ключем в нижнем регистре
			for _, value := range values {
				paramStrings = append(paramStrings, fmt.Sprintf("%s=%s", url.QueryEscape(strings.ToLower(key)), url.QueryEscape(value)))
			}
		}
	}

	// сортируем параметры запроса
	sort.Strings(paramStrings)
	canonicalQuery = strings.Join(paramStrings, "&")

	// создаем заголовки канонического запроса
	canonicalHeaders := createCanonicalHeadersV4(r.Header)
	signedHeaders := createSignedHeadersV4(r.Header)
	payloadHash := calculateSHA256(payload)

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
	// создание ключа для подписи запроса
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#derive-signing-key
	kDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")

	return kSigning
}

func createStringToSignV4(r *http.Request, canonicalRequest, region, service string) string {
	// создаем строку для подписи
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-string-to-sign
	algorithm := "AWS4-HMAC-SHA256"
	date := r.Header.Get("X-Amz-Date")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date[:8], region, service)
	canonicalRequestHash := calculateSHA256(canonicalRequest)

	return fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		date,
		scope,
		canonicalRequestHash,
	)
}

func hmacSHA256(key []byte, data string) []byte {
	// хэширующая функция
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func calculateSignatureV4(signingKey []byte, stringToSign string) string {
	// создаем строку подписи (подписываем stringToSign ключем signingKey)
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}
