// Copyright 2021 Polar Signals Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"net/http"
	"os"

	"github.com/go-kit/kit/log/level"
)

func main() {
	node := os.Args[1]
	logger := NewLogger("debug", LogFormatLogfmt, "")
	ctx := context.Background()
	m, err := NewPodManager(logger, node)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	go m.Run(ctx)

	go func() {
		var err error
		err = http.ListenAndServe(":8080", m)
		if err != nil {
			level.Error(logger).Log("err", err)
		}
	}()

	<-ctx.Done()
}
