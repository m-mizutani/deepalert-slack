package main

type Arguments arguments

func Handler(args Arguments) error {
	return handler(arguments(args))
}

var ReportToMessage = reportToMessage
