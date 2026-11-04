package stogashttp

import (
	"errors"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// pairWaits remembers, on this gateway, each customer credential and
// deployment whose provider asked callers to wait longer than a retry waits.
// Until the wait ends, a later request passes over that pair while another
// remains, instead of spending a call that the provider refuses: providers
// count refused calls against the limit (OpenAI) or say that earlier retries
// fail (Anthropic). A pair that is the request's last still gets its call,
// since a smaller request can pass a token limit that refused a larger one.
// Stogas's own credentials have no entry: their transport keeps its own waits.
type pairWaits struct {
	mu      sync.Mutex
	waiting map[pairKey]pairWait
}

type pairKey struct{ credential, deployment string }

type pairWait struct {
	until  time.Time
	answer catalog.APIError // the provider failure as its caller got it
}

// maxPairWaits bounds the memory. A full table records no new wait until an
// old one ends, which costs only the calls that the table would have saved.
const maxPairWaits = 4096

// waitingPair is a pair that the plan passed over during its wait.
type waitingPair struct{ until time.Time }

func (w waitingPair) Error() string { return "the provider asked callers to wait" }

func (w waitingPair) RetryAfter() time.Duration { return time.Until(w.until) }

func pairWaitKey(keyConfig *billing.KeyConfigSnapshot, provider schemas.ModelProvider, index int, deployment string) (pairKey, bool) {
	credential := keyConfig.CustomerCredentialID(string(provider), index)
	return pairKey{credential, deployment}, credential != ""
}

func (w *pairWaits) set(key pairKey, wait pairWait) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.waiting == nil {
		w.waiting = make(map[pairKey]pairWait)
	}
	if _, ok := w.waiting[key]; !ok && len(w.waiting) >= maxPairWaits {
		now := time.Now()
		for other, recorded := range w.waiting {
			if !recorded.until.After(now) {
				delete(w.waiting, other)
			}
		}
		if len(w.waiting) >= maxPairWaits {
			return
		}
	}
	w.waiting[key] = wait
}

func (w *pairWaits) clear(key pairKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.waiting, key)
}

// refusal is the error of a pair that still waits, or nil. It answers as the
// provider's failure did, with what remains of the wait.
func (w *pairWaits) refusal(key pairKey) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	wait, ok := w.waiting[key]
	if !ok {
		return nil
	}
	if !wait.until.After(time.Now()) {
		delete(w.waiting, key)
		return nil
	}
	return errors.Join(waitingPair{wait.until}, wait.answer)
}

// recordWait records the bound pair's failed call when its provider asked for
// a wait longer than a retry waits, after which the pair can serve again.
func (r *providerRun) recordWait(f *runFailure) {
	if r.action != retryPair || f.until.Sub(f.at) <= retryMaxWait {
		return
	}
	resolution := r.pair.Resolution
	key, ok := pairWaitKey(r.keyConfig, resolution.Provider, resolution.CredentialIndex, resolution.Deployment.ID)
	if !ok {
		return
	}
	detail, _ := f.response.payload["error"].(map[string]any)
	message, _ := detail["message"].(string)
	kind, _ := detail["type"].(string)
	r.server.pairWaits.set(key, pairWait{until: f.until, answer: catalog.APIError{
		Code: f.response.code(), StatusCode: f.response.status, Type: kind, Message: message,
	}})
}

// clearWait forgets the wait of the bound pair, which served.
func (r *providerRun) clearWait() {
	if r.pair == nil || r.pair.Resolution == nil {
		return
	}
	resolution := r.pair.Resolution
	if key, ok := pairWaitKey(r.keyConfig, resolution.Provider, resolution.CredentialIndex, resolution.Deployment.ID); ok {
		r.server.pairWaits.clear(key)
	}
}
