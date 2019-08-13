package main

type Arguments arguments

func Handler(args Arguments) (bool, error) {
	return handler(arguments(args))
}

var ReportToMessage = reportToMessage
