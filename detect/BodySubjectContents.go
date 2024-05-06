package detect

import (
	"github.com/sg3des/eml"
	"strings"
)

var (
	suspiciousSubjectLine = []string{
		"Urgent",
		"Verification required",
		"Invoice",
		"Need urgent help!",
		"Suspicious Outlook acivitity",
		"Important! Your password is about to expire",
		"Action required",
		"Fail",
		"Notice",
	}

	suspiciousBody = []string{
		"A vulnerability has been identified in",
		"To perform verification, click the link",
		"Please click here to install latest",
		"account has been locked",
		"fail",
	}
)

func CheckForSuspiciousWords(email *eml.Message) (words []string, sus bool) {

	//making slice, that holds all suspicious body
	words = make([]string, 0, len(suspiciousSubjectLine)+len(suspiciousBody))

	//checking suspicious words in email body
	body := strings.ToLower(string(email.Body))
	for _, word := range suspiciousBody {
		word = strings.ToLower(word)
		if strings.Contains(body, word) {
			sus = true
			words = append(words, word)
		}
	}

	subject := strings.ToLower(email.Subject)
	for _, word := range suspiciousSubjectLine {
		if strings.Contains(subject, word) {
			sus = true
			words = append(words, word)
		}
	}

	return
}
