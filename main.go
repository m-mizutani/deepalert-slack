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
	"github.com/sirupsen/logrus"

	// "github.com/nlopes/slack"
	"github.com/m-mizutani/slack"
)

var logger = logrus.New()

type arguments struct {
	Report         deepalert.Report
	SecretArn      string
	IgnoreSeverity string
	MessagePrefix  string
	SlackURL       string
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

func reportToMessage(report deepalert.Report, messagePrefix string) (*slack.WebhookMessage, error) {
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

	var attachments []slack.Attachment
	alert := report.Alerts[0]

	/*
		for _, attr := range alert.Attributes {
			field := slack.AttachmentField{
				Title: attr.Key,
				Value: attr.Value,
			}

			if attr.Type != "" {
				field.Title = fmt.Sprintf("%s (%s)", attr.Key, attr.Type)
			}
			fields = append(fields, field)
		}
	*/

	attachment := slack.Attachment{
		Title:      fmt.Sprintf("Rule: %s", alert.RuleName),
		AuthorName: alert.Detector,
		Text:       alert.Description,
		Color:      color,
		Fields: []slack.AttachmentField{
			{
				Title: "Report ID",
				Value: string(report.ID),
			},
			{
				Title: "Severity",
				Value: string(report.Result.Severity),
			},
		},
	}
	attachments = append(attachments, attachment)

	msg := slack.WebhookMessage{
		Attachments: attachments,
	}

	return &msg, nil
}

type slackSecrets struct {
	SlackURL string `json:"slack_url"`
}

func handler(args arguments) (bool, error) {
	var slackURL string

	if args.SlackURL == "" {
		logger.WithField("secretsArn", args.SecretArn).Info("SLACK_URL is not set, use SecretsManager instead")
		var secrets slackSecrets
		if err := getSecretValues(args.SecretArn, &secrets); err != nil {
			return false, errors.Wrapf(err, "Fail to get values from SecretsManager: %s", args.SecretArn)
		}
		slackURL = secrets.SlackURL
	} else {
		logger.Info("Use SLACK_URL")
		slackURL = args.SlackURL
	}

	// Skip if the report is not published
	if !args.Report.IsPublished() {
		logger.WithField("status", args.Report.Status).Info("Report is not published")
		return false, nil
	}

	// Skip if the report does not have alert (why?)
	if len(args.Report.Alerts) == 0 {
		logger.Warn("Report does not have alert")
		return false, nil
	}

	// If true, a report of the severity will be dropped.
	filter := map[string]bool{}
	for _, sev := range strings.Split(args.IgnoreSeverity, ",") {
		filter[sev] = true
	}

	if drop, ok := filter[string(args.Report.Result.Severity)]; ok && drop {
		return false, nil
	}

	msg, err := reportToMessage(args.Report, args.MessagePrefix)
	if err != nil {
		return false, errors.Wrapf(err, "Fail to build slack message")
	}

	if err := slack.PostWebhook(slackURL, msg); err != nil {
		return false, errors.Wrapf(err, "Fail to send slack message: %v", msg)
	}

	return true, nil
}

func lambdaHandler(ctx context.Context, report deepalert.Report) error {
	logger.WithField("report", report).Info("Start handler")

	args := arguments{
		Report:         report,
		IgnoreSeverity: os.Getenv("IGNORE_SEVERITY"),
		MessagePrefix:  os.Getenv("MESSAGE_PREFIX"),
		SlackURL:       os.Getenv("SLACK_URL"),
		SecretArn:      os.Getenv("SECRET_ARN"),
	}

	result, err := handler(args)
	logger.WithFields(logrus.Fields{
		"result": result,
		"args":   args,
	}).Info("Done handler")

	if err != nil {
		logger.WithError(err).Error("Fail to post slack message")
	}

	return err
}

func main() {
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)
	deepalert.StartEmitter(lambdaHandler)
}
