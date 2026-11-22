package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

func TestGetUsernameAvailability_LowercasesMixedCaseInput(t *testing.T) {
	var got string
	svc := &mockSvc{
		checkUsername: func(ctx context.Context, username string) (proto.UsernameAvailability, error) {
			got = username
			return proto.UsernameAvailability{Username: username, Available: true}, nil
		},
	}
	r := chi.NewRouter()
	r.Get("/usernames/{username}", identity.NewHandlers(svc).GetUsernameAvailability)

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/usernames/NassJ", nil))

	assert.Equal(t, "nassj", got)
}

func TestPostAccount_LowercasesMixedCaseUsername(t *testing.T) {
	var got string
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			got = req.Username
			return proto.CreateAccountResponse{AccountID: "acc-1"}, nil
		},
	}
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "NassJ"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	identity.NewHandlers(svc).PostAccount(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "nassj", got)
}
