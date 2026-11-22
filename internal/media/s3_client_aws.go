package media

import (
	"context"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type AWSConfig struct {
	Region string
	Bucket string
}

type AWSClient struct {
	bucket    string
	client    *s3.Client
	presigner *s3.PresignClient
}

func NewAWSClient(ctx context.Context, cfg AWSConfig) (*AWSClient, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, err
	}
	return NewAWSClientFromConfig(awsCfg, cfg.Bucket), nil
}

// NewAWSClientFromConfig builds a client from an already-loaded AWS config.
func NewAWSClientFromConfig(awsCfg aws.Config, bucket string) *AWSClient {
	cli := s3.NewFromConfig(awsCfg)
	return &AWSClient{
		bucket:    bucket,
		client:    cli,
		presigner: s3.NewPresignClient(cli),
	}
}

// PresignPut signs ContentLength into the URL: content-length becomes a signed
// header, so S3 rejects (SignatureDoesNotMatch) a PUT whose body is any other
// size. Without it the URL accepted any object up to S3's 5 GB single-PUT
// limit regardless of the size_bytes the client declared (and the server
// size-checked) at init.
func (a *AWSClient) PresignPut(ctx context.Context, key string, sizeBytes int64, expires time.Duration) (string, error) {
	p, err := a.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(a.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(sizeBytes),
	}, s3.WithPresignExpires(expires))
	if err != nil {
		return "", err
	}
	return p.URL, nil
}

func (a *AWSClient) PresignGet(ctx context.Context, key string, expires time.Duration) (string, error) {
	p, err := a.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expires))
	if err != nil {
		return "", err
	}
	return p.URL, nil
}

func (a *AWSClient) DeleteObject(ctx context.Context, key string) error {
	_, err := a.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})
	return err
}

// PutObject uploads exactly size bytes from body (server to S3 stays inside AWS).
func (a *AWSClient) PutObject(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	_, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(a.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	return err
}

// GetObject streams the object directly from S3 (server→S3 stays inside AWS).
// The caller MUST close the returned Body.
func (a *AWSClient) GetObject(ctx context.Context, key string) (*ObjectStream, error) {
	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	contentType := ""
	if out.ContentType != nil {
		contentType = *out.ContentType
	}
	length := int64(-1)
	if out.ContentLength != nil {
		length = *out.ContentLength
	}
	return &ObjectStream{
		ContentType:   contentType,
		ContentLength: length,
		Body:          out.Body,
	}, nil
}
