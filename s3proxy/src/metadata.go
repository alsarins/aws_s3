package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type ObjectMetadata struct {
	Size uint64
	Etag string
}

func SerializeObjectMetadata(m *ObjectMetadata, w io.Writer) error {
	TraceLogger.Println("Where:", "SerializeObjectMetadata")
	_, err := w.Write([]byte{S3ProxyMetadataVersion})

	if err != nil {
		return err
	}

	encodedSize := make([]byte, 8)
	n := binary.PutUvarint(encodedSize, m.Size)

	_, err = w.Write(encodedSize[0:n])

	if err != nil {
		return err
	}

	_, err = io.Copy(w, strings.NewReader(m.Etag))

	TraceLogger.Println("Where:", "end SerializeObjectMetadata")

	return err
}

func UnserializeObjectMetadata(r io.Reader) (*ObjectMetadata, error) {
	TraceLogger.Println("Where:", "UnserializeObjectMetadata")
	bufReader := bufio.NewReader(r)

	metadataVersion := make([]byte, 1)

	if n, err := bufReader.Read(metadataVersion); err != nil || n != len(metadataVersion) {
		return nil, fmt.Errorf("Cannot read metadata version: %s", err)
	}

	if metadataVersion[0] != S3ProxyMetadataVersion {
		return nil, fmt.Errorf("Invalid metadata version: %x", metadataVersion)
	}

	size, err := binary.ReadUvarint(bufReader)

	if err != nil {
		return nil, err
	}

	etag, err := io.ReadAll(bufReader)

	if err != nil {
		return nil, err
	}

	TraceLogger.Println("Where:", "end UnserializeObjectMetadata")
	return &ObjectMetadata{
		size,
		string(etag),
	}, nil
}

func (h *ProxyHandler) UpdateObjectMetadata(objectUrl *url.URL, metadata *ObjectMetadata, originalHeaders http.Header, info *BucketInfo) error {
	TraceLogger.Println("Where:", "UpdateObjectMetadata")
	if info == nil || info.Config == nil {
		return nil
	}

	serializedMetadata := bytes.NewBuffer(nil)

	err := SerializeObjectMetadata(metadata, serializedMetadata)

	if err != nil {
		return err
	}

	encReader, _, err := SetupWriteEncryption(bytes.NewReader(serializedMetadata.Bytes()), info)

	if err != nil {
		return err
	}

	encryptedMetadata, err := io.ReadAll(encReader)

	if err != nil {
		return err
	}

	requestUrl := *objectUrl

	var objectPath string

	if info.VirtualHost {
		objectPath = info.Name + requestUrl.Path
	} else {
		objectPath = requestUrl.Path
	}

	metadataRequest, err := http.NewRequest("PUT", objectUrl.String(), nil)

	if err != nil {
		return err
	}

	metadataRequest.Header.Set("x-amz-copy-source", objectPath)
	metadataRequest.Header.Set("x-amz-metadata-directive", "REPLACE")
	metadataRequest.Header.Set(S3ProxyMetadataHeader, fmt.Sprintf("%x", encryptedMetadata))

	for k, vs := range originalHeaders {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") || k == S3ProxyMetadataHeader {
			continue
		}

		metadataRequest.Header[k] = vs
	}

	// metadata has empty Body (we do not overwrite file in s3). Pass it to signature with empty Body
	metadataRequest.Header.Set("Content-Length", "0")
	err = h.SignRequestV4(metadataRequest, info, []byte(""))

	if err != nil {
		return err
	}

	metadataResponse, err := h.client.Do(metadataRequest)

	TraceLogger.Println("Where:", "end UpdateObjectMetadata")
	if err != nil {
		return err
	}

	if metadataResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected HTTP status: %s", metadataResponse.Status)
	}

	defer metadataResponse.Body.Close()

	return nil
}
