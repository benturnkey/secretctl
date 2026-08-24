package turnkeyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL         = "https://api.turnkey.com"
	defaultRequestTimeout  = 30 * time.Second
	defaultActivityTimeout = 60 * time.Second
	defaultPollInterval    = 500 * time.Millisecond
	maxResponseBytes       = 2 << 20
)

type Stamper interface {
	Stamp([]byte) (string, error)
}

type Client struct {
	baseURL         string
	httpClient      *http.Client
	stamper         Stamper
	now             func() time.Time
	pollInterval    time.Duration
	activityTimeout time.Duration
}

type ClientOption func(*Client)

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(client *Client) {
		client.httpClient = httpClient
	}
}

func WithPollConfig(interval, timeout time.Duration) ClientOption {
	return func(client *Client) {
		client.pollInterval = interval
		client.activityTimeout = timeout
	}
}

func WithClock(now func() time.Time) ClientOption {
	return func(client *Client) {
		client.now = now
	}
}

func NewClient(baseURL string, stamper Stamper, options ...ClientOption) (*Client, error) {
	if stamper == nil {
		return nil, errors.New("stamper is required")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	client := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: defaultRequestTimeout,
		},
		now:             time.Now,
		pollInterval:    defaultPollInterval,
		activityTimeout: defaultActivityTimeout,
		stamper:         stamper,
	}
	for _, option := range options {
		option(client)
	}
	if client.httpClient == nil {
		return nil, errors.New("HTTP client is required")
	}
	if client.pollInterval <= 0 || client.activityTimeout <= 0 {
		return nil, errors.New("activity polling interval and timeout must be positive")
	}

	return client, nil
}

func (c *Client) InitImportSecrets(ctx context.Context, organizationID string) (*InitImportSecretsResult, error) {
	request := activityEnvelope[initImportSecretsIntent]{
		Type:           "ACTIVITY_TYPE_INIT_IMPORT_SECRETS",
		TimestampMs:    strconv.FormatInt(c.now().UnixMilli(), 10),
		OrganizationID: organizationID,
		Parameters: initImportSecretsIntent{
			EncryptionSuite: TransportEncryptionSuiteEnclaveEncryptV1,
			NumSecrets:      1,
		},
	}

	var response activityResponse
	if err := c.postJSON(ctx, "/public/v1/submit/init_import_secrets", request, &response); err != nil {
		return nil, fmt.Errorf("submit init import secrets activity: %w", err)
	}

	completed, err := c.waitForActivity(ctx, organizationID, response.Activity)
	if err != nil {
		return nil, fmt.Errorf("wait for init import secrets activity: %w", err)
	}
	if completed.Result.InitImportSecretsResult == nil {
		return nil, errors.New("init import secrets activity completed without a result")
	}

	return completed.Result.InitImportSecretsResult, nil
}

func (c *Client) ImportSecrets(ctx context.Context, organizationID string, secret ImportSecretParams) (*ImportSecretsResult, error) {
	request := activityEnvelope[importSecretsIntent]{
		Type:           "ACTIVITY_TYPE_IMPORT_SECRETS",
		TimestampMs:    strconv.FormatInt(c.now().UnixMilli(), 10),
		OrganizationID: organizationID,
		Parameters: importSecretsIntent{
			Secrets: []ImportSecretParams{secret},
		},
	}

	var response activityResponse
	if err := c.postJSON(ctx, "/public/v1/submit/import_secrets", request, &response); err != nil {
		return nil, fmt.Errorf("submit import secrets activity: %w", err)
	}

	completed, err := c.waitForActivity(ctx, organizationID, response.Activity)
	if err != nil {
		return nil, fmt.Errorf("wait for import secrets activity: %w", err)
	}
	if completed.Result.ImportSecretsResult == nil {
		return nil, errors.New("import secrets activity completed without a result")
	}

	return completed.Result.ImportSecretsResult, nil
}

func (c *Client) ListSecrets(ctx context.Context, request ListSecretsRequest) (*ListSecretsResponse, error) {
	var response ListSecretsResponse
	if err := c.postJSON(ctx, "/public/v1/query/list_secrets", request, &response); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	return &response, nil
}

func (c *Client) waitForActivity(ctx context.Context, organizationID string, current activity) (*activity, error) {
	pollContext, cancel := context.WithTimeout(ctx, c.activityTimeout)
	defer cancel()

	for {
		switch current.Status {
		case activityStatusCompleted:
			return &current, nil
		case activityStatusFailed, activityStatusRejected:
			return nil, newActivityError(current)
		case activityStatusCreated, activityStatusPending, activityStatusConsensusNeeded, activityStatusAuthenticatorsNeeded:
			// Continue polling below.
		default:
			return nil, fmt.Errorf("unknown Turnkey activity status %q", current.Status)
		}

		select {
		case <-pollContext.Done():
			return nil, fmt.Errorf("activity %s did not complete: %w", current.ID, pollContext.Err())
		case <-time.After(c.pollInterval):
		}

		var response activityResponse
		request := getActivityRequest{OrganizationID: organizationID, ActivityID: current.ID}
		if err := c.postJSON(pollContext, "/public/v1/query/get_activity", request, &response); err != nil {
			return nil, fmt.Errorf("get activity %s: %w", current.ID, err)
		}
		current = response.Activity
	}
}

func newActivityError(activity activity) error {
	err := &ActivityError{Status: activity.Status}
	if activity.Failure != nil && activity.Failure.Code != nil {
		err.RPCCode = *activity.Failure.Code
	}
	if activity.Failure != nil && activity.Failure.Message != nil {
		err.message = *activity.Failure.Message
	}
	return err
}

func (c *Client) postJSON(ctx context.Context, path string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	stamp, err := c.stamper.Stamp(body)
	if err != nil {
		return fmt.Errorf("stamp request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Client-Version", "secretctl/0.1.0")
	request.Header.Set("X-Stamp", stamp)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send HTTP request: %w", err)
	}

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil {
		return fmt.Errorf("read HTTP response: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close HTTP response: %w", closeErr)
	}
	if len(responseBody) > maxResponseBytes {
		return errors.New("turnkey API response exceeded size limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return parseResponseError(response.StatusCode, responseBody)
	}
	if err := json.Unmarshal(responseBody, output); err != nil {
		return fmt.Errorf("decode HTTP response: %w", err)
	}

	return nil
}

func parseResponseError(statusCode int, body []byte) error {
	parsed := rpcStatus{}
	_ = json.Unmarshal(body, &parsed)

	err := &ResponseError{StatusCode: statusCode}
	if parsed.Code != nil {
		err.RPCCode = *parsed.Code
	}
	if parsed.Message != nil {
		err.message = *parsed.Message
	}
	return err
}
