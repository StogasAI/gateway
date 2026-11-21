package stogas

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// Gateways check stored credentials themselves and take the checks from PostgreSQL as workers take
// jobs from a queue: each gateway claims credentials whose checks are due, checks them and records
// the results, and each record sets when the next check is due. A claim holds the credential for
// two minutes and moves the due time to then, so a check that a gateway loses to a crash or a
// restart is due again then. A member or Control asks for a check by making it due now, and the
// claim takes each organization's oldest ask ahead of the scheduled checks. The checks that the
// fleet runs at once grow with its gateways.
const (
	// Stored checks take all of the checker's slots but one, which stays for the members' checks and
	// Control's probes that someone waits for.
	storedCheckLimit = byokCheckLimit - 1
	// A gateway looks for due checks when it starts, about this often after that, a fifth sooner or
	// later at random so that gateways spread out, and again as soon as one of its checks ends.
	storedCheckPoll = 5 * time.Second
	// A check ends well before its claim does, so no other gateway claims it meanwhile.
	storedCheckTimeout = 90 * time.Second
)

// errStoredCheckStopped is a check that this gateway stopped, which says nothing about the
// credential, so nothing is recorded.
var errStoredCheckStopped = errors.New("stored check stopped")

type storedCheckStore interface {
	ClaimByokChecks(context.Context, int) ([]*billing.ByokCheckTarget, error)
	OpenStored(*billing.ByokCheckTarget) (string, error)
	RecordByokCheck(context.Context, *billing.ByokCheckTarget, string, *billing.AzureDiscoveryResult) (*billing.ByokCheckRecord, error)
	RecordByokCheckFailure(context.Context, *billing.ByokCheckTarget) error
}

// runStoredChecks claims and runs due checks until ctx ends, and then waits for the checks that run.
func runStoredChecks(ctx context.Context, store storedCheckStore, checker *byokChecker) {
	var checks sync.WaitGroup
	defer checks.Wait()
	// Each running check sends once, so the buffer takes every send after the loop stops reading.
	ended := make(chan struct{}, storedCheckLimit)
	running := 0
	poll := time.NewTimer(0)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ended:
			running--
		case <-poll.C:
			poll.Reset(storedCheckDelay())
		}
		if running == storedCheckLimit {
			continue
		}
		targets, err := store.ClaimByokChecks(ctx, storedCheckLimit-running)
		if err != nil {
			if ctx.Err() == nil {
				writeOperationalLog(operationalLogEvent{Event: "stored_check_failed", ReasonCode: "claim_failed", ErrorType: safeOperationalErrorType(err), Severity: "warning"})
			}
			continue
		}
		for _, target := range targets {
			running++
			checks.Add(1)
			go func() {
				defer checks.Done()
				runStoredCheck(ctx, store, checker, target)
				ended <- struct{}{}
			}()
		}
	}
}

func storedCheckDelay() time.Duration {
	return storedCheckPoll*4/5 + rand.N(storedCheckPoll*2/5)
}

// runStoredCheck checks a claimed credential and records the result. A failure of ours, a secret
// that this gateway cannot open or that cannot serve the target stored beside it, is recorded as
// one, which the credential shows and operators are alerted to. A check that stops for any other
// reason records nothing, so the credential is due again when the claim ends.
func runStoredCheck(ctx context.Context, store storedCheckStore, checker *byokChecker, target *billing.ByokCheckTarget) {
	err := checkStored(ctx, store, checker, target)
	reason := ""
	switch {
	case err == nil, errors.Is(err, billing.ErrByokCheckChanged), errors.Is(err, billing.ErrByokCheckNotFound):
		// A newer check, a new secret or a deletion made this check moot.
		return
	case errors.Is(err, billing.ErrStoredByokSecret):
		reason = "secret_unreadable"
	case errors.Is(err, billing.ErrStoredByokTarget):
		reason = "target_mismatch"
	default:
		if ctx.Err() == nil {
			writeOperationalLog(operationalLogEvent{Event: "stored_check_failed", ReasonCode: "check_stopped", ErrorType: safeOperationalErrorType(err), Severity: "warning"})
		}
		return
	}
	if err := store.RecordByokCheckFailure(ctx, target); err != nil && ctx.Err() == nil {
		reason = "record_failed"
	}
	writeOperationalLog(operationalLogEvent{Event: "stored_check_failed", ReasonCode: reason, Severity: "error"})
}

func checkStored(ctx context.Context, store storedCheckStore, checker *byokChecker, target *billing.ByokCheckTarget) error {
	secret, err := store.OpenStored(target)
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, storedCheckTimeout)
	defer cancel()
	// The check holds the secret to the target that requests hold it to.
	found, failure, err := checker.run(checkCtx, target.Grant.OrganizationID, target.Provider, secret, target.Target, target.AzureAccountID, target.StartedAt)
	if err != nil || checkCtx.Err() != nil {
		// A check cut short by this gateway's bound or shutdown cannot tell what the provider says.
		return errStoredCheckStopped
	}
	if failure, err = storedByokFailure(target.Provider, failure); err != nil {
		return err
	}
	message, discovery := failure.message, (*billing.AzureDiscoveryResult)(nil)
	if found != nil {
		message, discovery = azureDiscoveryOutcome(found, nil)
	}
	_, err = store.RecordByokCheck(ctx, target, message, discovery)
	return err
}
