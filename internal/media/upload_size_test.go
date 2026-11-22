package media_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/media"
)

// Upload size bypass: a presigned PUT must only accept the size the client
// declared (and the server size-checked) at init.

func TestInitUpload_PresignsTheDeclaredSize(t *testing.T) {
	svc, _, s3 := newSvc()
	req := validUploadReq()
	req.SizeBytes = 4242

	_, err := svc.InitUpload(context.Background(), "acct-1", "dev-1", req)

	require.NoError(t, err)
	assert.Equal(t, int64(4242), s3.presignedSize)
}

// newOfflineAWSClient builds a real AWSClient with static credentials;
// presigning is local signing only, so no network or AWS account is involved.
func newOfflineAWSClient() *media.AWSClient {
	return media.NewAWSClientFromConfig(aws.Config{
		Region: "us-west-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret"}, nil
		}),
	}, "test-bucket")
}

func TestAWSClient_PresignPut_SignsContentLength(t *testing.T) {
	raw, err := newOfflineAWSClient().PresignPut(context.Background(), "media/m-1", 4242, 15*time.Minute)
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	signed := strings.Split(u.Query().Get("X-Amz-SignedHeaders"), ";")
	assert.Contains(t, signed, "content-length")
}
