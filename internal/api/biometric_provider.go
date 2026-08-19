package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
)

var errBiometricProviderUnavailable = errors.New("biometric provider is not configured")

type selfie struct {
	Data        []byte
	ContentType string
}

type biometricProvider interface {
	Enroll(ctx context.Context, subject string, image selfie) (string, error)
	Verify(ctx context.Context, templateID string, image selfie) (bool, error)
	Delete(ctx context.Context, templateID string) error
}

type unavailableBiometricProvider struct{}

func (unavailableBiometricProvider) Enroll(context.Context, string, selfie) (string, error) {
	return "", errBiometricProviderUnavailable
}
func (unavailableBiometricProvider) Verify(context.Context, string, selfie) (bool, error) {
	return false, errBiometricProviderUnavailable
}
func (unavailableBiometricProvider) Delete(context.Context, string) error {
	return errBiometricProviderUnavailable
}

type httpBiometricProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func configuredBiometricProvider(cfg Config) biometricProvider {
	if cfg.BiometricProviderURL == "" {
		return unavailableBiometricProvider{}
	}
	return &httpBiometricProvider{baseURL: cfg.BiometricProviderURL, token: cfg.BiometricProviderToken, client: http.DefaultClient}
}

func (p *httpBiometricProvider) Enroll(ctx context.Context, subject string, image selfie) (string, error) {
	var out struct {
		TemplateID string `json:"template_id"`
	}
	if err := p.multipart(ctx, http.MethodPost, "/v1/enrollments", map[string]string{"subject": subject}, image, &out); err != nil {
		return "", err
	}
	if out.TemplateID == "" {
		return "", errors.New("biometric provider returned an empty template id")
	}
	return out.TemplateID, nil
}

func (p *httpBiometricProvider) Verify(ctx context.Context, templateID string, image selfie) (bool, error) {
	var out struct {
		Matched bool `json:"matched"`
	}
	err := p.multipart(ctx, http.MethodPost, "/v1/verifications", map[string]string{"template_id": templateID}, image, &out)
	return out.Matched, err
}

func (p *httpBiometricProvider) Delete(ctx context.Context, templateID string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.baseURL+"/v1/enrollments/"+url.PathEscape(templateID), nil)
	if err != nil {
		return err
	}
	p.authorize(request)
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("biometric provider delete returned %d", response.StatusCode)
	}
	return nil
}

func (p *httpBiometricProvider) multipart(ctx context.Context, method, path string, fields map[string]string, image selfie, out any) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return err
		}
	}
	part, err := writer.CreateFormFile("selfie", "selfie")
	if err != nil {
		return err
	}
	if _, err = part.Write(image.Data); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, &body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-Selfie-Content-Type", image.ContentType)
	p.authorize(request)
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, response.Body)
		return fmt.Errorf("biometric provider returned %d", response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func (p *httpBiometricProvider) authorize(request *http.Request) {
	if p.token != "" {
		request.Header.Set("Authorization", "Bearer "+p.token)
	}
}
