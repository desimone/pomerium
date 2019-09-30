package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/grpcutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	pbAuthorize "github.com/pomerium/pomerium/proto/authorize"
	"github.com/pomerium/pomerium/proxy"
)

var versionFlag = flag.Bool("version", false, "prints the version")
var configFile = flag.String("config", "", "Specify configuration file location")

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
}

func run() error {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.FullVersion())
		return nil
	}
	opt, err := config.ParseOptions(*configFile)
	if err != nil {
		return err
	}
	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")
	// since we can have multiple listeners, we create a wait group
	var wg sync.WaitGroup
	setupMetrics(opt, &wg)
	setupTracing(opt)
	setupHTTPRedirectServer(opt, &wg)

	r := newGlobalRouter(opt)
	_, err = newAuthenticateService(*opt, r)
	if err != nil {
		return err
	}
	authz, err := newAuthorizeService(*opt, &wg)
	if err != nil {
		return err
	}

	proxy, err := newProxyService(*opt, r)
	if err != nil {
		return err
	}
	if proxy != nil {
		defer proxy.AuthorizeClient.Close()
	}

	go viper.WatchConfig()

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("cmd/pomerium: config file changed")
		opt = config.HandleConfigUpdate(*configFile, opt, []config.OptionsUpdater{authz, proxy})
	})

	srv, err := httputil.NewServer(httpServerOptions(opt), r, &wg)
	if err != nil {
		return err
	}
	go httputil.Shutdown(srv)
	// Blocks and waits until ALL WaitGroup members have signaled completion
	wg.Wait()
	return nil
}

func newAuthenticateService(opt config.Options, r *mux.Router) (*authenticate.Authenticate, error) {
	if !config.IsAuthenticate(opt.Services) {
		return nil, nil
	}
	service, err := authenticate.New(opt)
	if err != nil {
		return nil, err
	}
	sr := r.Host(urlutil.StripPort(opt.AuthenticateURL.Host)).Subrouter()
	sr.PathPrefix("/").Handler(service.Handler())

	return service, nil
}

func newAuthorizeService(opt config.Options, wg *sync.WaitGroup) (*authorize.Authorize, error) {
	if !config.IsAuthorize(opt.Services) {
		return nil, nil
	}
	service, err := authorize.New(opt)
	if err != nil {
		return nil, err
	}
	regFn := func(s *grpc.Server) {
		pbAuthorize.RegisterAuthorizerServer(s, service)
	}
	so := &grpcutil.ServerOptions{
		Addr:      opt.GRPCAddr,
		SharedKey: opt.SharedKey,
	}
	if !opt.GRPCInsecure {
		so.TLSCertificate = opt.TLSCertificate
	}
	grpcSrv := grpcutil.NewServer(so, regFn, wg)
	go grpcutil.Shutdown(grpcSrv)
	return service, nil
}

func newProxyService(opt config.Options, r *mux.Router) (*proxy.Proxy, error) {
	if !config.IsProxy(opt.Services) {
		return nil, nil
	}
	service, err := proxy.New(opt)
	if err != nil {
		return nil, err
	}
	r.PathPrefix("/").Handler(service.Handler)
	return service, nil
}

func newGlobalRouter(o *config.Options) *mux.Router {
	mux := httputil.NewRouter()
	mux.SkipClean(true)
	mux.Use(metrics.HTTPMetricsHandler(o.Services))
	mux.Use(log.NewHandler(log.Logger))
	mux.Use(log.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		log.FromRequest(r).Debug().
			Dur("duration", duration).
			Int("size", size).
			Int("status", status).
			Str("email", r.Header.Get(proxy.HeaderEmail)).
			Str("group", r.Header.Get(proxy.HeaderGroups)).
			Str("method", r.Method).
			Str("service", o.Services).
			Str("host", r.Host).
			Str("path", r.URL.String()).
			Msg("http-request")
	}))
	if len(o.Headers) != 0 {
		mux.Use(middleware.SetHeaders(o.Headers))
	}
	mux.Use(log.ForwardedAddrHandler("fwd_ip"))
	mux.Use(log.RemoteAddrHandler("ip"))
	mux.Use(log.UserAgentHandler("user_agent"))
	mux.Use(log.RefererHandler("referer"))
	mux.Use(log.RequestIDHandler("req_id", "Request-Id"))
	mux.Use(middleware.Healthcheck("/ping", version.UserAgent()))
	return mux
}

func setupMetrics(opt *config.Options, wg *sync.WaitGroup) {
	if opt.MetricsAddr != "" {
		if handler, err := metrics.PrometheusHandler(); err != nil {
			log.Error().Err(err).Msg("cmd/pomerium: metrics failed to start")
		} else {
			metrics.SetBuildInfo(opt.Services)
			metrics.RegisterInfoMetrics()
			serverOpts := &httputil.ServerOptions{Addr: opt.MetricsAddr}
			srv, _ := httputil.NewServer(serverOpts, handler, wg)
			go httputil.Shutdown(srv)
		}
	}
}

func setupTracing(opt *config.Options) {
	if opt.TracingProvider != "" {
		tracingOpts := &trace.TracingOptions{
			Provider:                opt.TracingProvider,
			Service:                 opt.Services,
			Debug:                   opt.TracingDebug,
			JaegerAgentEndpoint:     opt.TracingJaegerAgentEndpoint,
			JaegerCollectorEndpoint: opt.TracingJaegerCollectorEndpoint,
		}
		if err := trace.RegisterTracing(tracingOpts); err != nil {
			log.Error().Err(err).Msg("cmd/pomerium: couldn't register tracing")
		} else {
			log.Info().Interface("options", tracingOpts).Msg("cmd/pomerium: metrics configured")
		}
	}
}

func setupHTTPRedirectServer(opt *config.Options, wg *sync.WaitGroup) {
	if opt.HTTPRedirectAddr != "" {
		serverOpts := httputil.ServerOptions{Addr: opt.HTTPRedirectAddr}
		srv, _ := httputil.NewServer(&serverOpts, httputil.RedirectHandler(), wg)
		go httputil.Shutdown(srv)
	}
}

func httpServerOptions(opt *config.Options) *httputil.ServerOptions {
	return &httputil.ServerOptions{
		Addr:              opt.Addr,
		TLSCertificate:    opt.TLSCertificate,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		IdleTimeout:       opt.IdleTimeout,
	}
}
