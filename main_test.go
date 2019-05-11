package main_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/go-playground/assert.v1"

	"github.com/m-mizutani/deepalert"
	main "github.com/m-mizutani/deepalert-slack"
)

func makeReport() deepalert.Report {
	report := deepalert.Report{
		Alert: deepalert.Alert{
			RuleName:    "TestRule",
			Detector:    "TestDetector",
			Description: "This is a test",
			Attributes: []deepalert.Attribute{
				{
					Type:  deepalert.TypeIPAddr,
					Value: "10.2.3.4",
					Key:   "remote ip addr",
				},
				{
					Type:  deepalert.TypeUserName,
					Value: "mizutani",
					Key:   "remote user",
				},
			},
		},
		Result: deepalert.ReportResult{
			Severity: deepalert.SevUrgent,
			Reason:   "beacuse it's test",
		},
	}

	return report
}
func TestHandler(t *testing.T) {
	report := makeReport()
	secretArn := os.Getenv("DA_TEST_SECRET")
	if secretArn == "" {
		t.Skip("DA_TEST_SECRET is not set")
	}

	args := main.Arguments{
		Report:    report,
		SecretArn: secretArn,
	}
	err := main.Handler(args)
	require.NoError(t, err)
	// Confirm only no error
}

func TestReportToMessage(t *testing.T) {
	report := makeReport()
	msg, err := main.ReportToMessage(report)
	require.NoError(t, err)

	assert.Equal(t, "Rule: TestRule", msg.Attachments[0].Title)
	assert.Equal(t, 3, len(msg.Attachments[0].Fields))
}
