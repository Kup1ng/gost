package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"

	_ "net/http/pprof"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

var (
	configureFile string
	baseCfg       = &baseConfig{}
	pprofAddr     string
	pprofEnabled  = os.Getenv("PROFILING") != ""
)

func init() {
	gost.SetLogger(&gost.LogLogger{})

	var (
		printVersion bool
	)

	flag.Var(&baseCfg.route.ChainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&baseCfg.route.ServeNodes, "L", "listen address, can listen on multiple ports (required)")
	flag.IntVar(&baseCfg.route.Mark, "M", 0, "Specify out connection mark")
	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.StringVar(&baseCfg.route.Interface, "I", "", "Interface to bind")
	flag.BoolVar(&baseCfg.Debug, "D", false, "enable debug log")
	flag.BoolVar(&printVersion, "V", false, "print version")
	if pprofEnabled {
		flag.StringVar(&pprofAddr, "P", ":6060", "profiling HTTP server address")
	}

	// Kernel NAT forwarding mode (opt-in; Linux only). See README "NAT mode".
	flag.BoolVar(&baseCfg.NAT, "NAT", false, "enable kernel NAT (in-kernel DNAT) forwarding for all -L rules (Linux, root; incompatible with -F)")
	flag.BoolVar(&natCleanup, "nat-cleanup", false, "remove gost NAT rules and exit (scoped to -L if given, otherwise ALL gost rules)")
	flag.StringVar(&natBackend, "nat-backend", "auto", "NAT backend: auto|nftables|iptables")
	flag.IntVar(&natConntrackMax, "nat-conntrack-max", 0, "NAT mode: raise nf_conntrack_max to at least this value (0 = built-in floor)")
	flag.BoolVar(&natNoSNAT, "nat-no-snat", false, "NAT mode: do not add the scoped MASQUERADE rule (gateway/same-path topologies)")
	flag.BoolVar(&natNoForward, "nat-no-forward-rule", false, "NAT mode: do not add the scoped FORWARD accept rule")
	flag.BoolVar(&natAllowSSH, "nat-allow-ssh-port", false, "NAT mode: allow a -L listen port equal to the SSH port (dangerous)")
	flag.BoolVar(&natTuneTO, "nat-tune-timeouts", false, "NAT mode: also lower conntrack time_wait/fin_wait timeouts")

	flag.Parse()

	if printVersion {
		fmt.Fprintf(os.Stdout, "gost %s (%s %s/%s)\n",
			gost.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if configureFile != "" {
		_, err := parseBaseConfig(configureFile)
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
	}
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	// NAT-mode branches manage their own lifecycle and run cleanup via signal
	// handlers / deferred stop, so they must NOT go through the userspace path
	// (which blocks forever on select{}). Handled here in main(), not init(),
	// because init() uses os.Exit which would skip deferred cleanup.
	if natCleanup {
		os.Exit(runNATCleanup())
	}
	if baseCfg.NAT {
		os.Exit(runNAT())
	}

	if pprofEnabled {
		go func() {
			log.Log("profiling server on", pprofAddr)
			log.Log(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	// NOTE: as of 2.6, you can use custom cert/key files to initialize the default certificate.
	tlsConfig, err := tlsConfig(defaultCertFile, defaultKeyFile, "")
	if err != nil {
		// generate random self-signed certificate.
		cert, err := gost.GenCertificate()
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		log.Log("load TLS certificate files OK")
	}

	gost.DefaultTLSConfig = tlsConfig

	if err := start(); err != nil {
		log.Log(err)
		os.Exit(1)
	}

	select {}
}

func start() error {
	gost.Debug = baseCfg.Debug

	var routers []router
	rts, err := baseCfg.route.GenRouters()
	if err != nil {
		return err
	}
	routers = append(routers, rts...)

	for _, route := range baseCfg.Routes {
		rts, err := route.GenRouters()
		if err != nil {
			return err
		}
		routers = append(routers, rts...)
	}

	if len(routers) == 0 {
		return errors.New("invalid config")
	}
	for i := range routers {
		go routers[i].Serve()
	}

	return nil
}
