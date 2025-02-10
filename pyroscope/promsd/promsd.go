package promsd

import (
	"context"
	"fmt"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	promdiscovery "github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/kubernetes"
	"github.com/prometheus/prometheus/discovery/moby"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/sd"
	"os"
	"time"
)

// DefaultHTTPClientConfig for initializing objects
var DefaultHTTPClientConfig = config.HTTPClientConfig{
	FollowRedirects: true,
	EnableHTTP2:     true,
}

// Target refers to a singular discovered endpoint found by a discovery
// component.
type Target map[string]string

// Exports holds values which are exported by all discovery components.
type Exports struct {
	Targets []Target `alloy:"targets,attr"`
}

type DiscovererWithMetrics struct {
	discoverer     promdiscovery.Discoverer
	refreshMetrics promdiscovery.DiscovererMetrics
	sdMetrics      promdiscovery.DiscovererMetrics

	callback func(Exports)
	log      log.Logger
}

func NewK8SServiceDiscovery(logger log.Logger, callback func(exports Exports)) (*DiscovererWithMetrics, error) {
	//discovery.kubernetes "local_pods" {
	//	selectors {
	//		field = "spec.nodeName=" + env("HOSTNAME")
	//		role = "pod"
	//	}
	//	role = "pod"
	//}
	hostname := os.Getenv("HOSTNAME")
	_ = logger.Log("msg", "NewK8SServiceDiscovery", "hostname", hostname)
	cfg := &kubernetes.SDConfig{
		HTTPClientConfig: DefaultHTTPClientConfig,
		Role:             "pod",
		Selectors: []kubernetes.SelectorConfig{
			{
				Role:  "pod",
				Field: "spec.nodeName=" + hostname,
			},
		},
	}
	reg := prometheus.NewRegistry()
	return NewDiscovererWithMetrics(cfg, reg, logger, callback)
}

func NewDockerServiceDiscovery(logger log.Logger, callback func(exports Exports)) (*DiscovererWithMetrics, error) {
	cfg := &moby.DockerSDConfig{
		HTTPClientConfig: DefaultHTTPClientConfig,
		Host:             "unix:///var/run/docker.sock",
		RefreshInterval:  model.Duration(15 * time.Second),
	}
	reg := prometheus.NewRegistry()
	return NewDiscovererWithMetrics(cfg, reg, logger, callback)
}

func NewDiscovererWithMetrics(cfg promdiscovery.Config, reg prometheus.Registerer, logger log.Logger, callback func(exports Exports)) (*DiscovererWithMetrics, error) {
	refreshMetrics := promdiscovery.NewRefreshMetrics(reg)
	cfg.NewDiscovererMetrics(reg, refreshMetrics)

	sdMetrics := cfg.NewDiscovererMetrics(reg, refreshMetrics)

	discoverer, err := cfg.NewDiscoverer(promdiscovery.DiscovererOptions{
		Logger:  logger,
		Metrics: sdMetrics,
	})

	if err != nil {
		return nil, err
	}

	return &DiscovererWithMetrics{
		discoverer:     discoverer,
		refreshMetrics: refreshMetrics,
		sdMetrics:      sdMetrics,
		callback:       callback,
		log:            logger,
	}, nil
}

func (d *DiscovererWithMetrics) Run(ctx context.Context, up chan<- []*targetgroup.Group) {
	d.discoverer.Run(ctx, up)
}

func (d *DiscovererWithMetrics) Register() error {
	if err := d.refreshMetrics.Register(); err != nil {
		return err
	}
	return d.sdMetrics.Register()
}

func (d *DiscovererWithMetrics) Unregister() {
	d.refreshMetrics.Unregister()
	d.sdMetrics.Unregister()
}

// MaxUpdateFrequency is the minimum time to wait between updating targets.
// Prometheus uses a static threshold. Do not recommend changing this, except for tests.
var MaxUpdateFrequency = 5 * time.Second

// runDiscovery is a utility for consuming and forwarding target groups from a discoverer.
// It will handle collating targets (and clearing), as well as time based throttling of updates.
func (d *DiscovererWithMetrics) RunDiscovery(ctx context.Context) {
	// all targets we have seen so far
	cache := map[string]*targetgroup.Group{}

	ch := make(chan []*targetgroup.Group)
	runExited := make(chan struct{})
	go func() {
		err := d.Register()
		if err != nil {
			_ = level.Error(d.log).Log("msg", "failed to register discoverer metrics", "err", err)
		}
		defer d.Unregister()
		d.Run(ctx, ch)
		runExited <- struct{}{}
	}()

	// function to convert and send targets in format scraper expects
	send := func() {
		allTargets := []Target{}
		for _, group := range cache {
			for _, target := range group.Targets {
				labels := map[string]string{}
				// first add the group labels, and then the
				// target labels, so that target labels take precedence.
				for k, v := range group.Labels {
					labels[string(k)] = string(v)
				}
				for k, v := range target {
					labels[string(k)] = string(v)
				}
				allTargets = append(allTargets, labels)
			}
		}
		d.callback(Exports{Targets: allTargets})
	}

	ticker := time.NewTicker(MaxUpdateFrequency)
	// true if we have received new targets and need to send. Initially set it to true to send empty targets in case
	// the discoverer never sends any targets.
	haveUpdates := true
	for {
		select {
		case <-ticker.C:
			if haveUpdates {
				send()
				haveUpdates = false
			}
		case <-ctx.Done():
			// shut down the discoverer - send latest targets and wait for discoverer goroutine to exit
			send()
			<-runExited
			return
		case groups := <-ch:
			for _, group := range groups {
				// Discoverer will send an empty target set to indicate the group (keyed by Source field)
				// should be removed
				if len(group.Targets) == 0 {
					delete(cache, group.Source)
				} else {
					cache[group.Source] = group
				}
			}
			haveUpdates = true
		}
	}
}

func ConvertToPyroscopeTarget(target Target) sd.DiscoveryTarget {
	res := make(sd.DiscoveryTarget) // todo relabeling
	for k, v := range target {
		res[k] = v
		switch k {
		case "__meta_kubernetes_namespace":
			res["namespace"] = v
		case "__meta_kubernetes_pod_name":
			res["pod"] = v
		case "__meta_kubernetes_pod_node_name":
			res["node"] = v
		case "__meta_kubernetes_pod_container_name":
			res["container"] = v
		case "__meta_docker_container_name":
			res["container"] = v
		}

	}
	k8sNamespace := target["__meta_kubernetes_namespace"]
	k8sContainer := target["__meta_kubernetes_pod_container_name"]
	dockerContainer := target["__meta_docker_container_name"]
	if k8sNamespace != "" && k8sContainer != "" {
		svc := fmt.Sprintf("otel-ebpf/%s/%s", k8sNamespace, k8sContainer)
		res["service_name"] = svc
	} else if dockerContainer != "" {
		svc := fmt.Sprintf("otel-ebpf-docker/%s", dockerContainer)
		res["service_name"] = svc
	}

	return res
}
