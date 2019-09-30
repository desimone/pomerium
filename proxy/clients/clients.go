package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/grpcutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"

	"go.opencensus.io/plugin/ocgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
)

const defaultGRPCPort = 443

// Options contains options for connecting to a pomerium rpc service.
type Options struct {
	// Addr is the location of the service.  e.g. "service.corp.example:8443"
	Addr *url.URL
	// InternalAddr is the internal (behind the ingress) address to use when
	// making a connection. If empty, Addr is used.
	InternalAddr *url.URL
	// OverrideCertificateName overrides the server name used to verify the hostname on the
	// returned certificates from the server.  gRPC internals also use it to override the virtual
	// hosting name if it is set.
	OverrideCertificateName string
	// Shared secret is used to mutually authenticate a client and server.
	SharedSecret string
	// CA specifies the base64 encoded TLS certificate authority to use.
	CA string
	// CAFile specifies the TLS certificate authority file to use.
	CAFile string
	// RequestTimeout specifies the timeout for individual RPC calls
	RequestTimeout time.Duration
	// ClientDNSRoundRobin enables or disables DNS resolver based load balancing
	ClientDNSRoundRobin bool

	// WithInsecure disables transport security for  this ClientConn.
	// Note that transport security is required unless WithInsecure is set.
	WithInsecure bool
}

// NewGRPCClientConn returns a new gRPC pomerium service client connection.
func NewGRPCClientConn(opts *Options) (*grpc.ClientConn, error) {
	// gRPC uses a pre-shared secret middleware to establish authentication b/w server and client
	if opts.SharedSecret == "" {
		return nil, errors.New("proxy/clients: grpc client requires shared secret")
	}
	if opts.InternalAddr == nil && opts.Addr == nil {
		return nil, errors.New("proxy/clients: connection address required")

	}

	var connAddr string
	if opts.InternalAddr != nil {
		connAddr = opts.InternalAddr.Host
	} else {
		connAddr = opts.Addr.Host
	}
	// no colon exists in the connection string, assume one must be added manually
	if !strings.Contains(connAddr, ":") {
		connAddr = fmt.Sprintf("%s:%d", connAddr, defaultGRPCPort)
	}
	dialOptions := []grpc.DialOption{
		grpc.WithPerRPCCredentials(grpcutil.NewSharedSecretCred(opts.SharedSecret)),
		grpc.WithChainUnaryInterceptor(metrics.GRPCClientInterceptor("proxy"), grpcTimeoutInterceptor(opts.RequestTimeout)),
		grpc.WithStatsHandler(&ocgrpc.ClientHandler{}),
		grpc.WithDefaultCallOptions([]grpc.CallOption{grpc.WaitForReady(true)}...),
	}

	if opts.WithInsecure {
		log.Info().Str("addr", connAddr).Msg("proxy/clients: grpc with insecure")
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			log.Warn().Msg("proxy/clients: failed getting system cert pool making new one")
			rootCAs = x509.NewCertPool()
		}
		if opts.CA != "" || opts.CAFile != "" {
			var ca []byte
			var err error
			if opts.CA != "" {
				ca, err = base64.StdEncoding.DecodeString(opts.CA)
				if err != nil {
					return nil, fmt.Errorf("failed to decode certificate authority: %v", err)
				}
			} else {
				ca, err = ioutil.ReadFile(opts.CAFile)
				if err != nil {
					return nil, fmt.Errorf("certificate authority file %v not readable: %v", opts.CAFile, err)
				}
			}
			if ok := rootCAs.AppendCertsFromPEM(ca); !ok {
				return nil, fmt.Errorf("failed to append CA cert to certPool")
			}
			log.Debug().Msg("proxy/clients: added custom certificate authority")
		}

		cert := credentials.NewTLS(&tls.Config{RootCAs: rootCAs})

		// override allowed certificate name string, typically used when doing behind ingress connection
		if opts.OverrideCertificateName != "" {
			log.Debug().Str("cert-override-name", opts.OverrideCertificateName).Msg("proxy/clients: grpc")
			err := cert.OverrideServerName(opts.OverrideCertificateName)
			if err != nil {
				return nil, err
			}
		}
		// finally add our credential
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(cert))

	}

	if opts.ClientDNSRoundRobin {
		dialOptions = append(dialOptions, grpc.WithBalancerName(roundrobin.Name), grpc.WithDisableServiceConfig())
		connAddr = fmt.Sprintf("dns:///%s", connAddr)
	}
	return grpc.Dial(
		connAddr,
		dialOptions...,
	)
}

// grpcTimeoutInterceptor enforces per-RPC request timeouts
func grpcTimeoutInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if timeout <= 0 {
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)

	}
}
