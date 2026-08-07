package pkceflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	initTestIssuer      = "https://issuer.example"
	initTestRedirectURI = "http://127.0.0.1:9999/callback"
)

type initDiscoveryDocument struct {
	Issuer             string   `json:"issuer"`
	AuthorizationURL   string   `json:"authorization_endpoint"`
	TokenURL           string   `json:"token_endpoint"`
	JWKSURL            string   `json:"jwks_uri"`
	Algorithms         []string `json:"id_token_signing_alg_values_supported"`
	EndSessionEndpoint *string  `json:"end_session_endpoint,omitempty"`
}

type scriptedInitTransport struct {
	calls    chan *scriptedInitCall
	stopped  chan struct{}
	stopOnce sync.Once
}

type scriptedInitCall struct {
	request *http.Request
	result  chan scriptedInitResult
}

type scriptedInitResult struct {
	body []byte
	err  error
}

func newScriptedInitTransport() *scriptedInitTransport {
	return &scriptedInitTransport{
		calls:   make(chan *scriptedInitCall, 8),
		stopped: make(chan struct{}),
	}
}

// RoundTrip intentionally ignores request.Context so tests can release a stale
// discovery response after its Init generation has been canceled.
func (t *scriptedInitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	call := &scriptedInitCall{
		request: request,
		result:  make(chan scriptedInitResult, 1),
	}
	select {
	case t.calls <- call:
	case <-t.stopped:
		return nil, errors.New("scripted Init transport stopped")
	}
	var result scriptedInitResult
	select {
	case result = <-call.result:
	case <-t.stopped:
		return nil, errors.New("scripted Init transport stopped")
	}
	if result.err != nil {
		return nil, result.err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(result.body)),
		Request:    request,
	}, nil
}

func (t *scriptedInitTransport) stop() {
	t.stopOnce.Do(func() { close(t.stopped) })
}

func (c *scriptedInitCall) respond(body []byte) {
	c.result <- scriptedInitResult{body: body}
}

func (c *scriptedInitCall) fail(err error) {
	c.result <- scriptedInitResult{err: err}
}

type initRecordingEmitter struct {
	mu     sync.Mutex
	events []clientEvent
}

func (e *initRecordingEmitter) Emit(name string, data any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, clientEvent{name: name, data: data})
}

func (e *initRecordingEmitter) snapshot() []clientEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]clientEvent(nil), e.events...)
}

type committedInitSnapshot struct {
	provider           *oidc.Provider
	verifier           *oidc.IDTokenVerifier
	oauth2             *oauth2.Config
	endSessionEndpoint string
	refreshWake        chan struct{}
}

func newInitTestClient(
	t *testing.T,
	flow AuthFlowHandler,
	emitter EventEmitter,
) (*Client, *scriptedInitTransport) {
	t.Helper()
	if flow == nil {
		flow = &testFlowHandler{redirectURI: initTestRedirectURI}
	}
	if emitter == nil {
		emitter = noopEmitter{}
	}
	transport := newScriptedInitTransport()
	t.Cleanup(transport.stop)
	client, err := New(
		Config{IssuerURL: initTestIssuer, ClientID: "test-client"},
		flow,
		WithHTTPClient(&http.Client{Transport: transport}),
		WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, transport
}

func initDiscoveryBody(
	t *testing.T,
	issuer string,
	version string,
	includeEndSessionEndpoint bool,
) []byte {
	t.Helper()
	return initDiscoveryBodyWithAlgorithms(
		t,
		issuer,
		version,
		includeEndSessionEndpoint,
		[]string{"RS256"},
	)
}

func initDiscoveryBodyWithAlgorithms(
	t *testing.T,
	issuer string,
	version string,
	includeEndSessionEndpoint bool,
	algorithms []string,
) []byte {
	t.Helper()
	var endSessionEndpoint *string
	if includeEndSessionEndpoint {
		endpoint := initTestIssuer + "/logout/" + version
		endSessionEndpoint = &endpoint
	}
	body, err := json.Marshal(initDiscoveryDocument{
		Issuer:             issuer,
		AuthorizationURL:   initTestIssuer + "/authorize/" + version,
		TokenURL:           initTestIssuer + "/token/" + version,
		JWKSURL:            initTestIssuer + "/jwks/" + version,
		Algorithms:         algorithms,
		EndSessionEndpoint: endSessionEndpoint,
	})
	if err != nil {
		t.Fatalf("marshal discovery document: %v", err)
	}
	return body
}

func nextInitCall(t *testing.T, transport *scriptedInitTransport) *scriptedInitCall {
	t.Helper()
	select {
	case call := <-transport.calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("Init did not reach discovery transport")
		return nil
	}
}

func assertNoInitCall(t *testing.T, transport *scriptedInitTransport) {
	t.Helper()
	select {
	case call := <-transport.calls:
		call.fail(errors.New("unexpected discovery request"))
		t.Fatal("unexpected discovery request")
	default:
	}
}

func startInit(client *Client, ctx context.Context) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- client.Init(ctx)
	}()
	return result
}

func waitInitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Init did not return")
		return nil
	}
}

func runScriptedInit(
	t *testing.T,
	client *Client,
	transport *scriptedInitTransport,
	body []byte,
) error {
	t.Helper()
	result := startInit(client, context.Background())
	nextInitCall(t, transport).respond(body)
	return waitInitResult(t, result)
}

func captureInitSnapshot(client *Client) committedInitSnapshot {
	client.mu.Lock()
	defer client.mu.Unlock()
	return committedInitSnapshot{
		provider:           client.provider,
		verifier:           client.verifier,
		oauth2:             client.oauth2,
		endSessionEndpoint: client.endSessionEndpoint,
		refreshWake:        client.refreshWake,
	}
}

func assertInitSnapshotVersion(
	t *testing.T,
	snapshot committedInitSnapshot,
	version string,
	endSessionEndpoint string,
) {
	t.Helper()
	if snapshot.provider == nil || snapshot.verifier == nil || snapshot.oauth2 == nil {
		t.Fatalf("incomplete Init snapshot: %+v", snapshot)
	}
	if got, want := snapshot.oauth2.Endpoint.AuthURL, initTestIssuer+"/authorize/"+version; got != want {
		t.Fatalf("authorization endpoint = %q, want %q", got, want)
	}
	if got, want := snapshot.oauth2.Endpoint.TokenURL, initTestIssuer+"/token/"+version; got != want {
		t.Fatalf("token endpoint = %q, want %q", got, want)
	}
	if got := snapshot.oauth2.Endpoint.AuthStyle; got != oauth2.AuthStyleInParams {
		t.Fatalf("token endpoint auth style = %v, want %v", got, oauth2.AuthStyleInParams)
	}
	if got := snapshot.oauth2.RedirectURL; got != initTestRedirectURI {
		t.Fatalf("redirect URI = %q, want %q", got, initTestRedirectURI)
	}
	if got := snapshot.endSessionEndpoint; got != endSessionEndpoint {
		t.Fatalf("end-session endpoint = %q, want %q", got, endSessionEndpoint)
	}
	if snapshot.refreshWake == nil {
		t.Fatal("successful Init did not install refresh wake channel")
	}
}

func assertSameInitSnapshot(
	t *testing.T,
	got committedInitSnapshot,
	want committedInitSnapshot,
) {
	t.Helper()
	if got.provider != want.provider ||
		got.verifier != want.verifier ||
		got.oauth2 != want.oauth2 ||
		got.endSessionEndpoint != want.endSessionEndpoint ||
		got.refreshWake != want.refreshWake {
		t.Fatalf("Init snapshot changed:\n got: %+v\nwant: %+v", got, want)
	}
}

func assertInitEvents(t *testing.T, emitter *initRecordingEmitter, count int) {
	t.Helper()
	events := emitter.snapshot()
	if len(events) != count {
		t.Fatalf("events = %+v, want %d Init failure events", events, count)
	}
	for _, event := range events {
		if event.name != EventInitFailed || event.data != nil {
			t.Fatalf("event = %+v, want %q with nil data", event, EventInitFailed)
		}
	}
}

func TestInitPreCanceledContextIsNotAdmitted(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: context.Canceled,
		},
		{
			name: "deadline exceeded",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			emitter := &initRecordingEmitter{}
			client, transport := newInitTestClient(t, nil, emitter)
			ctx, cancel := test.context()
			defer cancel()

			err := client.Init(ctx)
			if !errors.Is(err, test.want) {
				t.Fatalf("Init error = %v, want errors.Is(%v)", err, test.want)
			}
			assertNoInitCall(t, transport)
			assertInitEvents(t, emitter, 0)
			if snapshot := captureInitSnapshot(client); snapshot.provider != nil || snapshot.refreshWake != nil {
				t.Fatalf("pre-canceled Init changed state: %+v", snapshot)
			}
			client.initMu.Lock()
			if client.initSeq != 0 || client.initOperation != nil {
				t.Fatalf("pre-canceled Init was admitted: seq=%d operation=%p", client.initSeq, client.initOperation)
			}
			client.initMu.Unlock()
		})
	}
}

func TestInitPreCanceledCallDoesNotSupersedeActiveOperation(t *testing.T) {
	emitter := &initRecordingEmitter{}
	client, transport := newInitTestClient(t, nil, emitter)
	activeResult := startInit(client, context.Background())
	activeCall := nextInitCall(t, transport)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Init(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled Init error = %v, want context.Canceled", err)
	}
	assertNoInitCall(t, transport)
	if err := activeCall.request.Context().Err(); err != nil {
		t.Fatalf("active Init context was canceled: %v", err)
	}

	activeCall.respond(initDiscoveryBody(t, initTestIssuer, "active", true))
	if err := waitInitResult(t, activeResult); err != nil {
		t.Fatalf("active Init: %v", err)
	}
	assertInitSnapshotVersion(t, captureInitSnapshot(client), "active", initTestIssuer+"/logout/active")
	assertInitEvents(t, emitter, 0)
}

func TestInitLatestSuccessFencesLateOlderSuccess(t *testing.T) {
	emitter := &initRecordingEmitter{}
	client, transport := newInitTestClient(t, nil, emitter)
	oldResult := startInit(client, context.Background())
	oldCall := nextInitCall(t, transport)
	newResult := startInit(client, context.Background())
	newCall := nextInitCall(t, transport)
	waitForTestSignal(t, oldCall.request.Context().Done(), "replacement did not cancel old discovery context")

	newCall.respond(initDiscoveryBody(t, initTestIssuer, "new", true))
	if err := waitInitResult(t, newResult); err != nil {
		t.Fatalf("new Init: %v", err)
	}
	committed := captureInitSnapshot(client)
	assertInitSnapshotVersion(t, committed, "new", initTestIssuer+"/logout/new")

	oldCall.respond(initDiscoveryBody(t, initTestIssuer, "old", true))
	if err := waitInitResult(t, oldResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("old Init error = %v, want context.Canceled", err)
	}
	assertSameInitSnapshot(t, captureInitSnapshot(client), committed)
	select {
	case <-committed.refreshWake:
		t.Fatal("late old Init closed the current refresh wake channel")
	default:
	}
	assertInitEvents(t, emitter, 0)
}

func TestInitLatestSuccessSuppressesLateOlderFailure(t *testing.T) {
	emitter := &initRecordingEmitter{}
	client, transport := newInitTestClient(t, nil, emitter)
	oldResult := startInit(client, context.Background())
	oldCall := nextInitCall(t, transport)
	newResult := startInit(client, context.Background())
	newCall := nextInitCall(t, transport)

	newCall.respond(initDiscoveryBody(t, initTestIssuer, "new", true))
	if err := waitInitResult(t, newResult); err != nil {
		t.Fatalf("new Init: %v", err)
	}
	committed := captureInitSnapshot(client)
	staleFailure := errors.New("stale discovery transport failure")
	oldCall.fail(staleFailure)
	err := waitInitResult(t, oldResult)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("old Init error = %v, want context.Canceled", err)
	}
	if errors.Is(err, staleFailure) {
		t.Fatalf("old Init leaked stale transport failure: %v", err)
	}
	assertSameInitSnapshot(t, captureInitSnapshot(client), committed)
	assertInitEvents(t, emitter, 0)
}

func TestInitCallerCancellationWinsLateTransportResult(t *testing.T) {
	tests := []struct {
		name             string
		transportFails   bool
		wantContextError error
	}{
		{name: "canceled valid response", wantContextError: context.Canceled},
		{name: "canceled transport failure", transportFails: true, wantContextError: context.Canceled},
		{name: "deadline valid response", wantContextError: context.DeadlineExceeded},
		{name: "deadline transport failure", transportFails: true, wantContextError: context.DeadlineExceeded},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			emitter := &initRecordingEmitter{}
			client, transport := newInitTestClient(t, nil, emitter)
			if err := runScriptedInit(
				t,
				client,
				transport,
				initDiscoveryBody(t, initTestIssuer, "baseline", true),
			); err != nil {
				t.Fatalf("baseline Init: %v", err)
			}
			baseline := captureInitSnapshot(client)

			ctx := newTriggeredInitContext(test.wantContextError)
			result := startInit(client, ctx)
			call := nextInitCall(t, transport)
			ctx.trigger()
			waitForTestSignal(t, call.request.Context().Done(), "caller context did not cancel discovery request")

			transportFailure := errors.New("late transport failure")
			if test.transportFails {
				call.fail(transportFailure)
			} else {
				call.respond(initDiscoveryBody(t, initTestIssuer, "late", true))
			}
			err := waitInitResult(t, result)
			if !errors.Is(err, test.wantContextError) {
				t.Fatalf("Init error = %v, want errors.Is(%v)", err, test.wantContextError)
			}
			if errors.Is(err, transportFailure) {
				t.Fatalf("Init leaked late transport failure: %v", err)
			}
			assertSameInitSnapshot(t, captureInitSnapshot(client), baseline)
			select {
			case <-baseline.refreshWake:
				t.Fatal("canceled Init closed the committed refresh wake channel")
			default:
			}
			assertInitEvents(t, emitter, 0)
		})
	}
}

// triggeredInitContext deterministically models caller cancellation after the
// discovery transport has admitted a request, including a deadline error.
type triggeredInitContext struct {
	done chan struct{}
	err  error
	once sync.Once
}

func newTriggeredInitContext(err error) *triggeredInitContext {
	return &triggeredInitContext{done: make(chan struct{}), err: err}
}

func (c *triggeredInitContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *triggeredInitContext) Done() <-chan struct{}       { return c.done }

func (c *triggeredInitContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

func (c *triggeredInitContext) Value(_ any) any { return nil }

func (c *triggeredInitContext) trigger() {
	c.once.Do(func() { close(c.done) })
}

func TestInitSupersededSuccessCannotCommitBeforeNewerCompletes(t *testing.T) {
	tests := []struct {
		name       string
		newerFails bool
	}{
		{name: "newer success"},
		{name: "newer failure", newerFails: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			emitter := &initRecordingEmitter{}
			client, transport := newInitTestClient(t, nil, emitter)
			if err := runScriptedInit(
				t,
				client,
				transport,
				initDiscoveryBody(t, initTestIssuer, "baseline", true),
			); err != nil {
				t.Fatalf("baseline Init: %v", err)
			}
			baseline := captureInitSnapshot(client)

			oldResult := startInit(client, context.Background())
			oldCall := nextInitCall(t, transport)
			newResult := startInit(client, context.Background())
			newCall := nextInitCall(t, transport)
			waitForTestSignal(t, oldCall.request.Context().Done(), "replacement did not cancel old discovery context")
			oldCall.respond(initDiscoveryBody(t, initTestIssuer, "stale", true))
			if err := waitInitResult(t, oldResult); !errors.Is(err, context.Canceled) {
				t.Fatalf("old Init error = %v, want context.Canceled", err)
			}
			assertSameInitSnapshot(t, captureInitSnapshot(client), baseline)
			select {
			case <-baseline.refreshWake:
				t.Fatal("stale Init woke observers before the newer result completed")
			default:
			}
			assertInitEvents(t, emitter, 0)

			if test.newerFails {
				newCall.respond(initDiscoveryBody(t, "https://wrong-issuer.example", "failed", true))
				newErr := waitInitResult(t, newResult)
				var mismatch *oidc.IssuerMismatchError
				if !errors.As(newErr, &mismatch) {
					t.Fatalf("new Init error = %v, want *oidc.IssuerMismatchError", newErr)
				}
				assertSameInitSnapshot(t, captureInitSnapshot(client), baseline)
				assertInitEvents(t, emitter, 1)
				return
			}

			newCall.respond(initDiscoveryBody(t, initTestIssuer, "new", true))
			if err := waitInitResult(t, newResult); err != nil {
				t.Fatalf("new Init: %v", err)
			}
			assertInitSnapshotVersion(t, captureInitSnapshot(client), "new", initTestIssuer+"/logout/new")
			assertInitEvents(t, emitter, 0)
		})
	}
}

func TestInitCurrentFailurePreservesSnapshotAndReportsOnce(t *testing.T) {
	emitter := &initRecordingEmitter{}
	client, transport := newInitTestClient(t, nil, emitter)
	if err := runScriptedInit(
		t,
		client,
		transport,
		initDiscoveryBody(t, initTestIssuer, "baseline", true),
	); err != nil {
		t.Fatalf("baseline Init: %v", err)
	}
	baseline := captureInitSnapshot(client)

	oldResult := startInit(client, context.Background())
	oldCall := nextInitCall(t, transport)
	newResult := startInit(client, context.Background())
	newCall := nextInitCall(t, transport)
	newCall.respond(initDiscoveryBody(t, "https://wrong-issuer.example", "failed", true))
	newErr := waitInitResult(t, newResult)
	var mismatch *oidc.IssuerMismatchError
	if !errors.As(newErr, &mismatch) {
		t.Fatalf("new Init error = %v, want *oidc.IssuerMismatchError", newErr)
	}
	assertSameInitSnapshot(t, captureInitSnapshot(client), baseline)
	assertInitEvents(t, emitter, 1)

	oldCall.respond(initDiscoveryBody(t, initTestIssuer, "stale", true))
	if err := waitInitResult(t, oldResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("old Init error = %v, want context.Canceled", err)
	}
	assertSameInitSnapshot(t, captureInitSnapshot(client), baseline)
	assertInitEvents(t, emitter, 1)
}

func TestInitSuccessfulRediscoveryClearsEndSessionEndpoint(t *testing.T) {
	client, transport := newInitTestClient(t, nil, nil)
	if err := runScriptedInit(
		t,
		client,
		transport,
		initDiscoveryBody(t, initTestIssuer, "first", true),
	); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	first := captureInitSnapshot(client)
	assertInitSnapshotVersion(t, first, "first", initTestIssuer+"/logout/first")

	if err := runScriptedInit(
		t,
		client,
		transport,
		initDiscoveryBody(t, initTestIssuer, "second", false),
	); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	second := captureInitSnapshot(client)
	assertInitSnapshotVersion(t, second, "second", "")
	if second.provider == first.provider || second.verifier == first.verifier || second.oauth2 == first.oauth2 {
		t.Fatal("rediscovery did not replace the complete discovery snapshot")
	}
	if second.refreshWake == first.refreshWake {
		t.Fatal("rediscovery did not replace the refresh wake channel")
	}
	select {
	case <-first.refreshWake:
	default:
		t.Fatal("rediscovery did not wake observers of the previous snapshot")
	}
}

type blockingInitRedirectFlow struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingInitRedirectFlow() *blockingInitRedirectFlow {
	return &blockingInitRedirectFlow{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (f *blockingInitRedirectFlow) StartAuthFlow(_ context.Context, _ string) (string, error) {
	return "", nil
}

func (f *blockingInitRedirectFlow) RedirectURI() string {
	f.enteredOnce.Do(func() { close(f.entered) })
	<-f.release
	return initTestRedirectURI
}

func (f *blockingInitRedirectFlow) unblock() {
	f.releaseOnce.Do(func() { close(f.release) })
}

func TestInitCancellationAfterDiscoveryDoesNotCommit(t *testing.T) {
	flow := newBlockingInitRedirectFlow()
	t.Cleanup(flow.unblock)
	emitter := &initRecordingEmitter{}
	client, transport := newInitTestClient(t, flow, emitter)
	ctx, cancel := context.WithCancel(context.Background())
	result := startInit(client, ctx)
	call := nextInitCall(t, transport)
	call.respond(initDiscoveryBody(t, initTestIssuer, "canceled", true))
	waitForTestSignal(t, flow.entered, "Init did not reach pre-commit redirect lookup")
	cancel()
	flow.unblock()

	if err := waitInitResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Init error = %v, want context.Canceled", err)
	}
	if snapshot := captureInitSnapshot(client); snapshot.provider != nil || snapshot.refreshWake != nil {
		t.Fatalf("canceled Init committed state: %+v", snapshot)
	}
	assertInitEvents(t, emitter, 0)
}

type reentrantInitEmitter struct {
	mu        sync.Mutex
	events    []clientEvent
	client    *Client
	result    chan error
	reentered sync.Once
}

func (e *reentrantInitEmitter) Emit(name string, data any) {
	e.mu.Lock()
	e.events = append(e.events, clientEvent{name: name, data: data})
	e.mu.Unlock()
	if name == EventInitFailed {
		e.reentered.Do(func() {
			e.result <- e.client.Init(context.Background())
		})
	}
}

func (e *reentrantInitEmitter) snapshot() []clientEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]clientEvent(nil), e.events...)
}

func TestInitFailureEmitterCanReenterInit(t *testing.T) {
	emitter := &reentrantInitEmitter{result: make(chan error, 1)}
	client, transport := newInitTestClient(t, nil, emitter)
	emitter.client = client
	outerResult := startInit(client, context.Background())
	outerCall := nextInitCall(t, transport)
	outerCall.respond(initDiscoveryBody(t, "https://wrong-issuer.example", "failed", true))

	reentrantCall := nextInitCall(t, transport)
	reentrantCall.respond(initDiscoveryBody(t, initTestIssuer, "reentrant", true))
	if err := waitInitResult(t, emitter.result); err != nil {
		t.Fatalf("reentrant Init: %v", err)
	}
	outerErr := waitInitResult(t, outerResult)
	var mismatch *oidc.IssuerMismatchError
	if !errors.As(outerErr, &mismatch) {
		t.Fatalf("outer Init error = %v, want *oidc.IssuerMismatchError", outerErr)
	}
	assertInitSnapshotVersion(
		t,
		captureInitSnapshot(client),
		"reentrant",
		initTestIssuer+"/logout/reentrant",
	)
	events := emitter.snapshot()
	if len(events) != 1 || events[0].name != EventInitFailed || events[0].data != nil {
		t.Fatalf("events = %+v, want one nil-payload %q", events, EventInitFailed)
	}
}
