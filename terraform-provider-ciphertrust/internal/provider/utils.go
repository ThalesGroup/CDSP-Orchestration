package provider

import "strings"

func trimString(data string) string {
	cleaned := strings.Trim(data, "\"")
	return cleaned
}
