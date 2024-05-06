package detect

import (
	"github.com/sg3des/eml"
	"log"
	"strings"
)

func CheckSenderValidity(email *eml.Message) {
	// getting domain name
	sender := email.Sender.Email()
	list := strings.Split(sender, "@")
	if len(list) < 2 {
		log.Fatal("FATAL could not retreive the domain name")
	}
	domain := list[1]

	for _, header := range email.FullHeaders {
		if header.Key == "Received" {
			values := strings.Split(header.Value, " ")
			if len(values) < 2 {
				log.Fatal("INVALID RECEIVED FORMAT ", len(values), header.Value)
			}
			if domain != values[1] {
				log.Printf("WARN the email might to be spoofed. Domain in senders email address and RECEIVED header do not match in email %s domain in RECEIVED header %s", domain, values[1])
			}
		}
	}

	//check if the repylto is empty
	replyTo := email.ReplyTo
	if len(replyTo) == 0 {
		log.Printf("WARN to return for %s", sender)
	} else {
		replyEmail := replyTo[0].Email()
		if replyEmail != sender {
			log.Printf("WARN sender and return path is not equal. Email adress sender %s and reply to : %s", sender, replyEmail)
		}
	}

}
