package systable

import (
	"fmt"
)

type Syscall struct {
	Number    uint16   `json:"number"`
	Name      string   `json:"name"`
	ManPage   string   `json:"man_page,omitempty"`
	Arguments []string `json:"arguments"`
}

func manPage(name string) string {
	if name == "_llseek" {
		name = "lseek"
	}
	return fmt.Sprintf("https://man7.org/linux/man-pages/man2/%s.2.html", name)
}
