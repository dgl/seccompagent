// Copyright 2020-2021 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux,cgo

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/seccompagent/pkg/agent"
	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/handlers/falco"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/registry"

	log "github.com/sirupsen/logrus"
)

var (
	socketFile    string
	resolverParam string
	logflags      string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
	flag.StringVar(&resolverParam, "resolver", "", "Container resolver to use [none, demo-basic, kubernetes]")
	flag.StringVar(&logflags, "log", "info", "log level [trace,debug,info,warn,error,fatal,color,nocolor,json]")
}

func main() {
	nsenter.Init()

	flag.Parse()
	for _, v := range strings.Split(logflags, ",") {
		if v == "json" {
			log.SetFormatter(&log.JSONFormatter{})
		} else if v == "color" {
			log.SetFormatter(&log.TextFormatter{ForceColors: true})
		} else if v == "nocolor" {
			log.SetFormatter(&log.TextFormatter{DisableColors: true})
		} else if lvl, err := log.ParseLevel(v); err == nil {
			log.SetLevel(lvl)
		} else {
			fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", err.Error())
			flag.Usage()
			os.Exit(1)
		}
	}
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(errors.New("invalid command"))
	}

	var resolver registry.ResolverFunc

	switch resolverParam {
	case "none", "":
		resolver = nil
	case "kubernetes":
		kubeResolverFunc := func(podCtx *kuberesolver.PodContext, metadata map[string]string) *registry.Registry {
			log.WithFields(log.Fields{
				"pod":      podCtx,
				"metadata": metadata,
			}).Debug("New container")

			r := registry.New()

			if v, ok := metadata["MIDDLEWARE"]; ok {
				for _, middleware := range strings.Split(v, ",") {
					switch middleware {
					case "falco":
						r.MiddlewareHandlers = append(r.MiddlewareHandlers, falco.NotifyFalco(podCtx))
					default:
						log.WithFields(log.Fields{
							"pod":        podCtx,
							"middleware": middleware,
						}).Error("Invalid middleware")
					}
				}
			}

			allowedFilesystems := map[string]struct{}{}
			if v, ok := metadata["MOUNT_CIFS"]; ok && v == "true" {
				allowedFilesystems["cifs"] = struct{}{}
			}
			if len(allowedFilesystems) > 0 {
				r.SyscallHandler["mount"] = handlers.Mount(allowedFilesystems)
			}
			return r
		}
		var err error
		resolver, err = kuberesolver.KubeResolver(kubeResolverFunc)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("invalid container resolver"))
	}

	err := agent.StartAgent(socketFile, resolver)
	if err != nil {
		panic(err)
	}
}
