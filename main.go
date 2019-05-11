package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/m-mizutani/deepalert"
	"github.com/pkg/errors"

	"github.com/nlopes/slack"
)

type arguments struct {
	Report    deepalert.Report
	SecretArn string
}

func getSecretValues(secretArn string, values interface{}) error {
	// sample: arn:aws:secretsmanager:ap-northeast-1:1234567890:secret:mytest
	arn := strings.Split(secretArn, ":")
	if len(arn) != 7 {
		return errors.New(fmt.Sprintf("Invalid SecretsManager ARN format: %s", secretArn))
	}
	region := arn[3]

	ssn := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	mgr := secretsmanager.New(ssn)

	result, err := mgr.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	})

	if err != nil {
		return errors.Wrap(err, "Fail to retrieve secret values")
	}

	err = json.Unmarshal([]byte(*result.SecretString), values)
	if err != nil {
		return errors.Wrap(err, "Fail to parse secret values as JSON")
	}

	return nil
}

func reportToMessage(report deepalert.Report) (*slack.WebhookMessage, error) {
	var color string
	switch report.Result.Severity {
	case deepalert.SevSafe:
		color = "#1BA466"
	case deepalert.SevUnclassified:
		color = "#F0BA32"
	case deepalert.SevUrgent:
		color = "#D04255"
	default:
		color = "#888888"
	}

	fields := []slack.AttachmentField{
		{
			Title: "Severity",
			Value: fmt.Sprintf("%s: %s", report.Result.Severity, report.Result.Reason),
		},
	}
	for _, attr := range report.Alert.Attributes {
		field := slack.AttachmentField{
			Title: attr.Key,
			Value: attr.Value,
		}

		if attr.Type != "" {
			field.Title = fmt.Sprintf("%s (%s)", attr.Key, attr.Type)
		}
		fields = append(fields, field)
	}

	lineDelim := "- - - - - - - - - -"
	attachment := slack.Attachment{
		Title:      fmt.Sprintf("Rule: %s", report.Alert.RuleName),
		AuthorName: report.Alert.Detector,
		Text:       report.Alert.Description + "\n" + lineDelim,
		Color:      color,
		Fields:     fields,
	}

	msg := slack.WebhookMessage{
		Text:        "DeepAlert Report of Security Alert",
		Attachments: []slack.Attachment{attachment},
	}

	return &msg, nil
}

type slackSecrets struct {
	SlackURL string `json:"slack_url"`
}

func handler(args arguments) error {
	var secrets slackSecrets
	if err := getSecretValues(args.SecretArn, &secrets); err != nil {
		return errors.Wrapf(err, "Fail to get values from SecretsManager: %s", args.SecretArn)
	}

	msg, err := reportToMessage(args.Report)
	if err != nil {
		return errors.Wrapf(err, "Fail to build slack message")
	}

	if err := slack.PostWebhook(secrets.SlackURL, msg); err != nil {
		return errors.Wrapf(err, "Fail to send slack message: %v", msg)
	}

	return nil
}

func lambdaHandler(ctx context.Context, report deepalert.Report) error {
	args := arguments{
		Report:    report,
		SecretArn: os.Getenv("SecretArn"),
	}
	return handler(args)
}

func main() {
	deepalert.StartEmitter(lambdaHandler)
}
