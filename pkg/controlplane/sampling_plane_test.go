package controlplane

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

func TestSamplingListActivateReset(t *testing.T) {
	p := NewSampling(map[string]SamplingConfig{"extractor": {Temperature: 0.1, MaxTokens: 900}})
	if got := p.List(); len(got) != 1 || got[0].Version != 0 {
		t.Fatalf("default should list at v0, got %+v", got)
	}
	pv := p.Activate("extractor", SamplingConfig{Temperature: 0, MaxTokens: 512, Seed: 42})
	if pv.Version != 1 || p.Config("extractor").Seed != 42 {
		t.Fatalf("activation should set seed 42 at v1, got %+v", pv)
	}
	if HashSampling(SamplingConfig{Seed: 1}) == HashSampling(SamplingConfig{Seed: 2}) {
		t.Fatal("different configs must hash differently")
	}
	if r := p.Reset("extractor"); r.Version != 0 || r.Config.MaxTokens != 900 {
		t.Fatalf("reset should restore the default, got %+v", r)
	}
}

func TestGovernedSamplingPersist(t *testing.T) {
	inv, _ := datastore.Open(":memory:")
	defer inv.Close()
	p := GovernedSampling(map[string]SamplingConfig{"extractor": {Temperature: 0.1}}, inv, nil)
	p.Activate("extractor", SamplingConfig{Temperature: 0.2, Seed: 7})
	cfg, ok, err := inv.LatestSampling("extractor")
	if err != nil || !ok || cfg == "" {
		t.Fatalf("activation should persist a sampling row, ok=%v err=%v cfg=%q", ok, err, cfg)
	}
}
