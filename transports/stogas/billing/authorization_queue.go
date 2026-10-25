package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// The authorizations of an organization that wait while its statement runs
	// share the next one, up to this many. authorize_gateway_holds accepts as
	// many.
	maxAuthorizationBatch = 64
	// A statement that finds its organization busy runs again after a random
	// pause below a limit that starts here and doubles each time up to
	// organizationBusyMaxPause.
	organizationBusyPause    = time.Millisecond
	organizationBusyMaxPause = 32 * time.Millisecond
)

// authorizationArguments are an authorization's arguments in the order of
// authorize_gateway_hold's parameters, under authorize_gateway_holds' keys.
// Times are whole microseconds, as PostgreSQL stores them, so that both
// functions receive the same values.
type authorizationArguments struct {
	HashedKey                *string         `json:"hashed_key"`
	KeyID                    *string         `json:"key_id"`
	DashboardActorUserID     *string         `json:"dashboard_actor_user_id"`
	DashboardSessionID       *string         `json:"dashboard_session_id"`
	RequestID                string          `json:"request_id"`
	HoldID                   string          `json:"hold_id"`
	ProviderKey              string          `json:"provider_key"`
	ProductKey               string          `json:"product_key"`
	EstimatedUpstreamCostUSD string          `json:"estimated_upstream_cost_usd"`
	ExpiresAt                time.Time       `json:"expires_at"`
	HoldParamsHash           string          `json:"hold_params_hash"`
	UpstreamTarget           json.RawMessage `json:"upstream_target"`
	EncryptionKeyID          *string         `json:"encryption_key_id"`
	AuthorizeBefore          time.Time       `json:"authorize_before"`
	ReservedTokens           int64           `json:"reserved_tokens"`
	ActiveUntil              time.Time       `json:"active_until"`
	CredentialsGeneration    int             `json:"credentials_generation"`
	CachedByok               json.RawMessage `json:"cached_byok"`
	PolicyVersions           *PolicyVersions `json:"policy_versions"`
	ActiveRules              any             `json:"active_rules"`
	InputTextBytes           int64           `json:"input_text_bytes"`
	NodeID                   *string         `json:"node_id"`
}

func (a *authorizationArguments) values(previousHoldID *string, finished []uuid.UUID) []any {
	return []any{
		a.HashedKey, a.KeyID, a.DashboardActorUserID, a.DashboardSessionID, a.RequestID, a.HoldID,
		a.ProviderKey, a.ProductKey, a.EstimatedUpstreamCostUSD, a.ExpiresAt, a.HoldParamsHash,
		nullableString(string(a.UpstreamTarget)), a.EncryptionKeyID, a.AuthorizeBefore, a.ReservedTokens,
		a.ActiveUntil, a.CredentialsGeneration, string(a.CachedByok), a.PolicyVersions, a.ActiveRules,
		a.InputTextBytes, a.NodeID, previousHoldID, finished,
	}
}

// pendingAuthorization waits in its organization's queue for a statement.
type pendingAuthorization struct {
	arguments authorizationArguments
	// previous is the hold that a move replaces.
	previous *string
	// A refusal that memory records for this credential while it waits holds
	// it back too.
	admissionKey string
	waitUntil    time.Time
	done         chan authorizationOutcome
	// The queue's lock guards these. A move, and an authorization of a batch
	// that PostgreSQL failed, runs alone. A taken authorization is in a
	// statement; left is why its caller stopped waiting meanwhile.
	alone, taken bool
	left         error
}

type authorizationOutcome struct {
	row     authorizeRow
	refusal error
	err     error
	// sent reports that err came after the statement reached PostgreSQL.
	sent bool
}

// organizationQueues runs an organization's authorizations in this gateway one
// statement at a time. They lock the same rows, and PostgreSQL runs one at a
// time across all gateways, so running more would only take more connections
// from every other organization. Those that arrive while a statement runs wait
// in order, holding nothing, and the next statement authorizes them together
// in one transaction and one turn of the organization's lock.
type organizationQueues struct {
	waits, busy, timeouts, batches, batched atomic.Uint64
	largestBatch, lastTimeoutAt             atomic.Int64
	shards                                  [localAdmissionShards]organizationQueueShard
}

type organizationQueueShard struct {
	mu     sync.Mutex
	queues map[string]*organizationQueue
}

// A queue lasts while it has authorizations to run, so admission bounds the map.
type organizationQueue struct {
	id      string
	shard   *organizationQueueShard
	waiting []*pendingAuthorization
}

func (q *organizationQueues) timedOut() {
	q.timeouts.Add(1)
	q.lastTimeoutAt.Store(time.Now().UTC().UnixMilli())
}

func (q *organizationQueues) recordBatch(size int) {
	q.batches.Add(1)
	q.batched.Add(uint64(size))
	for {
		largest := q.largestBatch.Load()
		if int64(size) <= largest || q.largestBatch.CompareAndSwap(largest, int64(size)) {
			return
		}
	}
}

// join queues an authorization and returns its queue, which needs a runner
// when it is new.
func (q *organizationQueues) join(organizationID string, p *pendingAuthorization) (*organizationQueue, bool) {
	shard := &q.shards[localAdmissionShard(organizationID)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	queue := shard.queues[organizationID]
	created := queue == nil
	if created {
		if shard.queues == nil {
			shard.queues = make(map[string]*organizationQueue)
		}
		queue = &organizationQueue{id: organizationID, shard: shard}
		shard.queues[organizationID] = queue
	} else {
		q.waits.Add(1)
	}
	queue.waiting = append(queue.waiting, p)
	return queue, created
}

// leave removes an authorization that no statement has, and reports whether
// it did. One that a statement has leaves when the statement returns it.
func (q *organizationQueue) leave(p *pendingAuthorization, reason error) bool {
	q.shard.mu.Lock()
	defer q.shard.mu.Unlock()
	if p.taken {
		p.left = reason
		return false
	}
	if index := slices.Index(q.waiting, p); index >= 0 {
		q.waiting = slices.Delete(q.waiting, index, index+1)
	}
	return true
}

// next returns the authorizations whose wait ended and when the last of the
// others stops waiting. It removes the queue when none waits.
func (q *organizationQueue) next(now time.Time) (expired []*pendingAuthorization, latest time.Time, ok bool) {
	q.shard.mu.Lock()
	defer q.shard.mu.Unlock()
	q.waiting = slices.DeleteFunc(q.waiting, func(p *pendingAuthorization) bool {
		if now.Before(p.waitUntil) {
			latest = later(latest, p.waitUntil)
			return false
		}
		p.taken = true
		expired = append(expired, p)
		return true
	})
	if len(q.waiting) == 0 {
		delete(q.shard.queues, q.id)
		return expired, latest, false
	}
	return expired, latest, true
}

// take removes up to limit authorizations from the front of the queue, or
// one that runs alone.
func (q *organizationQueue) take(limit int) []*pendingAuthorization {
	q.shard.mu.Lock()
	defer q.shard.mu.Unlock()
	count := 0
	for count < min(limit, len(q.waiting)) {
		alone := q.waiting[count].alone
		if alone && count > 0 {
			break
		}
		count++
		if alone {
			break
		}
	}
	taken := slices.Clone(q.waiting[:count])
	q.waiting = slices.Delete(q.waiting, 0, count)
	for _, p := range taken {
		p.taken = true
	}
	return taken
}

// putBack returns authorizations to the front of the queue in their order,
// except those whose caller left, which it returns.
func (q *organizationQueue) putBack(batch []*pendingAuthorization, alone bool) (left []*pendingAuthorization) {
	q.shard.mu.Lock()
	defer q.shard.mu.Unlock()
	batch = slices.DeleteFunc(slices.Clone(batch), func(p *pendingAuthorization) bool {
		if p.left != nil {
			left = append(left, p)
			return true
		}
		p.taken = false
		p.alone = p.alone || alone
		return false
	})
	q.waiting = slices.Insert(q.waiting, 0, batch...)
	return left
}

// authorizeInOrder runs an authorization after its organization's earlier ones.
// It leaves its queue when ctx ends first; once a statement has it, it waits
// for that statement.
func (s *Service) authorizeInOrder(ctx context.Context, organizationID string, p *pendingAuthorization) authorizationOutcome {
	queue, created := s.organizationQueues.join(organizationID, p)
	if created {
		go s.runOrganization(queue)
	}
	select {
	case outcome := <-p.done:
		return outcome
	case <-ctx.Done():
	}
	if !queue.leave(p, ctx.Err()) {
		return <-p.done
	}
	s.answerLeft(p, ctx.Err())
	return <-p.done
}

// answerLeft answers an authorization that stopped waiting without a statement.
func (s *Service) answerLeft(p *pendingAuthorization, reason error) {
	if errors.Is(reason, context.DeadlineExceeded) {
		s.organizationQueues.timedOut()
	}
	p.done <- authorizationOutcome{err: reason}
}

// runOrganization runs an organization's statements while authorizations wait.
// It takes a connection before them, so those that arrive while it waits for
// one join the statement.
func (s *Service) runOrganization(queue *organizationQueue) {
	pause := organizationBusyPause
	for {
		expired, latest, ok := queue.next(time.Now())
		for _, p := range expired {
			s.answerLeft(p, context.DeadlineExceeded)
		}
		if !ok {
			return
		}
		waitCtx, cancel := context.WithDeadline(context.Background(), latest)
		conn, err := s.db.pool.Acquire(waitCtx)
		cancel()
		if err != nil {
			// Waiting ended for those that were queued; any other failure is the
			// pool's or the database's and fails the next statement's
			// authorizations without a call.
			if !errors.Is(err, context.DeadlineExceeded) {
				s.authorizations.failed()
				for _, p := range queue.take(maxAuthorizationBatch) {
					p.done <- authorizationOutcome{err: err}
				}
			}
			continue
		}
		batch := s.withoutRefusals(queue.take(maxAuthorizationBatch))
		var retry []*pendingAuthorization
		failed := false
		if len(batch) > 0 {
			retry, failed = s.runAuthorizations(conn, batch, s.finalizations.finishedRequests(queue.id))
		}
		conn.Release()
		// A failed batch runs again one by one, so one bad request fails by
		// itself. A busy organization runs again after a pause.
		for _, p := range queue.putBack(retry, failed) {
			s.answerLeft(p, p.left)
		}
		if len(retry) == 0 {
			pause = organizationBusyPause
		} else if !failed {
			time.Sleep(rand.N(pause))
			pause = min(2*pause, organizationBusyMaxPause)
		}
	}
}

// withoutRefusals answers the first authorizations whose credential memory
// refused while they waited, and returns the rest.
func (s *Service) withoutRefusals(batch []*pendingAuthorization) []*pendingAuthorization {
	now := time.Now()
	return slices.DeleteFunc(batch, func(p *pendingAuthorization) bool {
		if p.previous != nil {
			return false
		}
		if err := s.refusals.get(p.admissionKey, now); err != nil {
			p.done <- authorizationOutcome{refusal: err}
			return true
		}
		return false
	})
}

// runAuthorizations runs one statement for the batch and answers its
// authorizations, except those to run again: all of a batch that PostgreSQL
// failed, and those that found their organization busy. Requests that
// finished on this gateway do not count against its concurrency limits.
func (s *Service) runAuthorizations(conn *pgxpool.Conn, batch []*pendingAuthorization, finished []uuid.UUID) (retry []*pendingAuthorization, failed bool) {
	deadline := batch[0].arguments.AuthorizeBefore
	for _, p := range batch[1:] {
		deadline = later(deadline, p.arguments.AuthorizeBefore)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	rows := make([]authorizeRow, len(batch))
	var err error
	if len(batch) == 1 {
		p := batch[0]
		err = conn.QueryRow(ctx, s.authorizeHoldQuery, p.arguments.values(p.previous, finished)...).Scan(rows[0].fields()...)
	} else {
		// An error, unlike a fatal one, rolled the whole batch back.
		var pgErr *pgconn.PgError
		if err = s.queryAuthorizations(ctx, conn, batch, finished, rows); errors.As(err, &pgErr) && pgErr.SeverityUnlocalized == "ERROR" {
			return batch, true
		}
	}
	if err != nil {
		s.authorizations.failed()
		for _, p := range batch {
			p.done <- authorizationOutcome{err: err, sent: true}
		}
		return nil, false
	}
	s.authorizations.answered()
	busy := false
	for i, p := range batch {
		if rows[i].Result == "organization_busy" {
			busy = true
			retry = append(retry, p)
			continue
		}
		p.done <- authorizationOutcome{row: rows[i], sent: true}
	}
	if busy {
		s.organizationQueues.busy.Add(1)
	}
	if answered := len(batch) - len(retry); answered > 1 {
		s.organizationQueues.recordBatch(answered)
	}
	return retry, false
}

// queryAuthorizations fills rows with authorize_gateway_holds' results in
// batch order.
func (s *Service) queryAuthorizations(ctx context.Context, conn *pgxpool.Conn, batch []*pendingAuthorization, finished []uuid.UUID, rows []authorizeRow) error {
	arguments := make([]*authorizationArguments, len(batch))
	for i, p := range batch {
		arguments[i] = &p.arguments
	}
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return err
	}
	result, err := conn.Query(ctx, s.authorizeHoldsQuery, encoded, finished)
	if err != nil {
		return err
	}
	var ordinal int64
	var row authorizeRow
	count := 0
	if _, err := pgx.ForEachRow(result, append([]any{&ordinal}, row.fields()...), func() error {
		if ordinal < 1 || ordinal > int64(len(rows)) || rows[ordinal-1].Result != "" {
			return fmt.Errorf("authorization batch returned position %d", ordinal)
		}
		rows[ordinal-1] = row
		count++
		return nil
	}); err != nil {
		return err
	}
	if count != len(rows) {
		return fmt.Errorf("authorization batch returned %d of %d results", count, len(rows))
	}
	return nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
