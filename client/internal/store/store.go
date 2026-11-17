// Package store wraps the MinIO off-chain object store.
package store

import (
	"bytes"
	"context"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Store struct {
	c      *minio.Client
	Bucket string
}

func New(endpoint, user, pass, bucket string) (*Store, error) {
	c, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(user, pass, ""), Secure: false})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if ok, _ := c.BucketExists(ctx, bucket); !ok {
		if err := c.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, err
		}
	}
	return &Store{c: c, Bucket: bucket}, nil
}

func (s *Store) Put(key string, b []byte) error {
	_, err := s.c.PutObject(context.Background(), s.Bucket, key, bytes.NewReader(b), int64(len(b)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return err
}

// Get returns nil, nil when the object does not exist.
func (s *Store) Get(key string) ([]byte, error) {
	o, err := s.c.GetObject(context.Background(), s.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer o.Close()
	b, err := io.ReadAll(o)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

func (s *Store) Remove(key string) error {
	return s.c.RemoveObject(context.Background(), s.Bucket, key, minio.RemoveObjectOptions{})
}

// List returns all keys under prefix.
func (s *Store) List(prefix string) ([]string, error) {
	var out []string
	for o := range s.c.ListObjects(context.Background(), s.Bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		out = append(out, o.Key)
	}
	return out, nil
}
