package main

import (
	"flag"
	"io"
	"log"

	"github.com/dzeromsk/pop3"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

var (
	address = flag.String("addr", ":995", "Address to listen to")
	cert    = flag.String("cert", "cert.pem", "TLS Certificate used by server")
	key     = flag.String("key", "key.pem", "TLS Private key used by server")
	region  = flag.String("region", "eu-west-1", "AWS S3 bucket region")
	bucket  = flag.String("bucket", "sns-example-com", "AWS S3 bucket name")
)

func main() {
	flag.Parse()

	err := pop3.ListenAndServeTLS(*address, *cert, *key, &s3auth{
		bucket: *bucket,
		region: *region,
	})
	if err != nil {
		log.Fatalln(err)
	}
}

type s3auth struct {
	bucket string
	region string
}

func (a *s3auth) Auth(user, pass string) (pop3.Maildropper, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(a.region),
		// Credentials: credentials.NewStaticCredentials(user, pass, ""),
	})
	if err != nil {
		return nil, err
	}

	maildrop := &s3maildrop{
		svc:    s3.New(sess),
		bucket: a.bucket,
	}

	return maildrop, nil
}

type s3maildrop struct {
	svc    *s3.S3
	bucket string
}

func (m *s3maildrop) List() (messages map[string]int, err error) {
	resp, err := m.svc.ListObjectsV2(
		&s3.ListObjectsV2Input{
			Bucket: aws.String(m.bucket),
		},
	)
	if err != nil {
		return nil, err
	}

	messages = make(map[string]int, len(resp.Contents))
	for _, item := range resp.Contents {
		messages[*item.Key] = int(*item.Size)
	}

	return messages, nil
}

func (m *s3maildrop) Get(key string, message io.Writer) (err error) {
	resp, err := m.svc.GetObject(
		&s3.GetObjectInput{
			Bucket: aws.String(m.bucket),
			Key:    aws.String(key),
		},
	)
	defer resp.Body.Close()

	_, err = io.Copy(message, resp.Body)
	return err
}

func (m *s3maildrop) Delete(key string) (err error) {
	_, err = m.svc.DeleteObject(
		&s3.DeleteObjectInput{
			Bucket: aws.String(m.bucket),
			Key:    aws.String(key),
		},
	)
	return err
}
