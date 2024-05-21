package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	// sets the TDD for all the tests
	cases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey 1234"},
			},
			expectedKey:   "1234",
			expectedError: nil,
		},
		{
			name:          "Empty authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed authorization header (No ApiKey)",
			headers: http.Header{
				"Authorization": []string{"Bearer 1234"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed authorization header (incorrect format)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	// iterate over all the test cases
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.expectedKey {
				t.Errorf("expected API key: %s, got: %s", tt.expectedKey, apiKey)
			}
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) {
				t.Errorf("expected error: %v, got: %v", tt.expectedError, err)
			}
			if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("expected error message: %v, got: %v", tt.expectedError, err)
			}
		})
	}
}
