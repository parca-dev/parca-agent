package template

import (
	_ "embed"
	"html/template"
	"time"

	"github.com/prometheus/prometheus/pkg/labels"
)

//go:embed statuspage.html
var StatusPageTemplateBytes []byte

var StatusPageTemplate = template.Must(template.New("statuspage").Parse(string(StatusPageTemplateBytes)))

//go:embed profileview.html
var ProfileViewTemplateBytes []byte

var ProfileViewTemplate = template.Must(template.New("profileview").Parse(string(ProfileViewTemplateBytes)))

type ActiveProfiler struct {
	Type         string
	Labels       labels.Labels
	LastTakenAgo time.Duration
	Error        error
	Link         string
}

type StatusPage struct {
	ActiveProfilers []ActiveProfiler
}
