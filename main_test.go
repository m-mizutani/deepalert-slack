package main_test

import (
	"os"
	"testing"

	"github.com/m-mizutani/deepalert"
	main "github.com/m-mizutani/deepalert-slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	SecretArn string
}

var testCfg testConfig

func init() {
	testCfg.SecretArn = os.Getenv("DA_TEST_SECRET")
}

func makeReport() deepalert.Report {
	report := deepalert.Report{
		Alerts: []deepalert.Alert{
			{
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

	if testCfg.SecretArn == "" {
		t.Skip("DA_TEST_SECRET is not set")
	}

	args := main.Arguments{
		Report:    report,
		SecretArn: testCfg.SecretArn,
	}
	res, err := main.Handler(args)
	require.NoError(t, err)
	assert.True(t, res)
	// Confirm only no error
}

func TestFilter1(t *testing.T) {
	if testCfg.SecretArn == "" {
		t.Skip("DA_TEST_SECRET is not set")
	}

	report := makeReport()
	report.Result.Severity = deepalert.SevSafe
	args := main.Arguments{
		Report:         report,
		SecretArn:      testCfg.SecretArn,
		SeverityFilter: "safe,unclassified",
	}
	res, err := main.Handler(args)
	require.NoError(t, err)
	assert.False(t, res)
}

func TestFilter2(t *testing.T) {
	if testCfg.SecretArn == "" {
		t.Skip("DA_TEST_SECRET is not set")
	}

	report := makeReport()
	report.Result.Severity = deepalert.SevUrgent
	args := main.Arguments{
		Report:         report,
		SecretArn:      testCfg.SecretArn,
		SeverityFilter: "safe,unclassified",
	}
	res, err := main.Handler(args)
	require.NoError(t, err)
	assert.True(t, res)
}

func TestMultipleAlerts(t *testing.T) {
	if testCfg.SecretArn == "" {
		t.Skip("DA_TEST_SECRET is not set")
	}

	report := makeReport()
	report.Result.Severity = deepalert.SevUnclassified
	report.Alerts = append(report.Alerts, deepalert.Alert{
		RuleName:    "Blue",
		Detector:    "Orange",
		Description: "This is a test 2",
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
	})

	args := main.Arguments{
		Report:         report,
		SecretArn:      testCfg.SecretArn,
		SeverityFilter: "safe",
	}
	res, err := main.Handler(args)
	require.NoError(t, err)
	assert.True(t, res)
}

func TestPrefix(t *testing.T) {
	if testCfg.SecretArn == "" {
		t.Skip("DA_TEST_SECRET is not set")
	}

	report := makeReport()
	report.Result.Severity = deepalert.SevUrgent
	args := main.Arguments{
		Report:        report,
		SecretArn:     testCfg.SecretArn,
		MessagePrefix: "@mizutani ",
	}
	res, err := main.Handler(args)
	require.NoError(t, err)
	assert.True(t, res)
}

func TestReportToMessage(t *testing.T) {
	report := makeReport()
	msg, err := main.ReportToMessage(report, "PREFIX")
	require.NoError(t, err)

	assert.Equal(t, "Rule: TestRule", msg.Attachments[0].Title)
}
