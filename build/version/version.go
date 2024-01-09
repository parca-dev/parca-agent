// Package version provides functions to obtain VCS information about the Parca components.
package version

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/magefile/mage/sh"
)

const (
	parcaReleaseURL = "https://api.github.com/repos/parca-dev/parca/releases/latest"

	unknownVersion = "unknown"
)

var (
	httpTimeout = time.Second * 5

	agentVersion  *string
	serverVersion *string
)

// Agent is the version of the agent.
func Agent() (string, error) {
	// TODO(kakkoyun): Convert pure Go.
	// https://github.com/go-git/go-git
	if agentVersion != nil {
		return *agentVersion, nil
	}

	version := unknownVersion
	hash, err := sh.Output("git", "log", "-n1", "--pretty='%h'")
	if err != nil {
		return version, err
	}
	taggedVersion, err := sh.Output("git", "describe", "--exact-match", "--tags", hash)
	if err == nil {
		return taggedVersion, nil
	}

	head, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return version, err
	}

	shortHead, err := sh.Output("git", "rev-parse", "--short", "HEAD")
	if err != nil {
		return version, err
	}

	version = fmt.Sprintf("%s-%s-%s", head, shortHead, hash)
	agentVersion = &version
	return version, nil
}

type payload struct {
	TagName string `json:"tag_name"` //nolint: tagliatelle
}

// Server is the version of the server.
func Server() (string, error) {
	if serverVersion != nil {
		return *serverVersion, nil
	}

	version := unknownVersion
	req, err := http.NewRequest(http.MethodGet, parcaReleaseURL, nil)
	if err != nil {
		return version, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return version, err
	}
	defer resp.Body.Close()

	var p payload
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return version, err
	}
	version = p.TagName

	serverVersion = &version
	return version, nil
}
