package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Incomplete Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := GetAPIKey(test.headers)

			// Check the returned API key
			if key != test.expectedKey {
				t.Errorf("expected key %q, got %q", test.expectedKey, key)
			}

			// Check the returned error
			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) || (err != nil && err.Error() != test.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}
