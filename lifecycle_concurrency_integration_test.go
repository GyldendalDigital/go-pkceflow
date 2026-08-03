package pkceflow_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
	"github.com/GyldendalDigital/go-pkceflow/mobileflow"
	"github.com/GyldendalDigital/go-pkceflow/oidctest"
)

const lifecycleRedirectURI = "http://127.0.0.1:9999/callback"

type scriptedLifecycleCall struct {
	kind    string
	ctx     context.Context
	proceed chan struct{}
	once    sync.Once
}

func (c *scriptedLifecycleCall) release() {
	c.once.Do(func() { close(c.proceed) })
}

type scriptedLifecycleFlow struct {
	inner              *oidctest.FakeFlowHandler
	redirectURI        string
	ignoreCancellation bool
	calls              chan *scriptedLifecycleCall
	active             atomic.Int32
	maxActive          atomic.Int32
}

func newScriptedLifecycleFlow(
	idp *oidctest.FakeIDPServer,
	ignoreCancellation bool,
) *scriptedLifecycleFlow {
	return &scriptedLifecycleFlow{
		inner:              oidctest.NewFakeFlowHandler(idp, lifecycleRedirectURI),
		redirectURI:        lifecycleRedirectURI,
		ignoreCancellation: ignoreCancellation,
		calls:              make(chan *scriptedLifecycleCall),
	}
}

func (f *scriptedLifecycleFlow) RedirectURI() string {
	return f.redirectURI
}

func (f *scriptedLifecycleFlow) PostLogoutRedirectURI() string {
	return f.redirectURI
}

func (f *scriptedLifecycleFlow) StartAuthFlow(
	ctx context.Context,
	authURL string,
) (string, error) {
	return f.run(ctx, "login", authURL)
}

func (f *scriptedLifecycleFlow) StartLogoutFlow(
	ctx context.Context,
	logoutURL string,
) (string, error) {
	return f.run(ctx, "logout", logoutURL)
}

func (f *scriptedLifecycleFlow) run(
	ctx context.Context,
	kind string,
	targetURL string,
) (string, error) {
	active := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		maximum := f.maxActive.Load()
		if active <= maximum || f.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}

	call := &scriptedLifecycleCall{
		kind:    kind,
		ctx:     ctx,
		proceed: make(chan struct{}),
	}
	if f.ignoreCancellation {
		f.calls <- call
		<-call.proceed
		return f.inner.StartAuthFlow(context.WithoutCancel(ctx), targetURL)
	}

	select {
	case f.calls <- call:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case <-call.proceed:
		return f.inner.StartAuthFlow(ctx, targetURL)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

type authorizationCodeTransport struct {
	base        http.RoundTripper
	gate        bool
	requests    atomic.Int32
	entered     chan struct{}
	gateClaimed atomic.Bool
	release     chan struct{}
	releaseOnce sync.Once
}

func newAuthorizationCodeTransport(gate bool) *authorizationCodeTransport {
	return &authorizationCodeTransport{
		base:    http.DefaultTransport,
		gate:    gate,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (t *authorizationCodeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	isAuthorizationCode, err := requestUsesAuthorizationCode(request)
	if err != nil {
		return nil, err
	}
	response, err := t.base.RoundTrip(request)
	if err != nil || !isAuthorizationCode {
		return response, err
	}

	t.requests.Add(1)
	if t.gate && t.gateClaimed.CompareAndSwap(false, true) {
		close(t.entered)
		<-t.release
	}
	return response, nil
}

func (t *authorizationCodeTransport) unblock() {
	t.releaseOnce.Do(func() { close(t.release) })
}

func requestUsesAuthorizationCode(request *http.Request) (bool, error) {
	if request.Method != http.MethodPost || request.Body == nil {
		return false, nil
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return false, err
	}
	_ = request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return false, err
	}
	return values.Get("grant_type") == "authorization_code", nil
}

type recordingLifecycleStore struct {
	inner       oidctest.MemoryStore
	mu          sync.Mutex
	operations  []string
	blockSave   bool
	saveEntered chan struct{}
	saveRelease chan struct{}
	saveOnce    sync.Once
}

func newRecordingLifecycleStore() *recordingLifecycleStore {
	return &recordingLifecycleStore{}
}

func newBlockingLifecycleStore() *recordingLifecycleStore {
	return &recordingLifecycleStore{
		blockSave:   true,
		saveEntered: make(chan struct{}),
		saveRelease: make(chan struct{}),
	}
}

func (s *recordingLifecycleStore) Save(state pkceflow.TokenState) error { //nolint:gocritic // hugeParam: interface requires value parameter
	s.record("save")
	if s.blockSave {
		s.saveOnce.Do(func() { close(s.saveEntered) })
		<-s.saveRelease
	}
	return s.inner.Save(state)
}

func (s *recordingLifecycleStore) Load() (pkceflow.TokenState, error) {
	return s.inner.Load()
}

func (s *recordingLifecycleStore) Delete() error {
	s.record("delete")
	return s.inner.Delete()
}

func (s *recordingLifecycleStore) record(operation string) {
	s.mu.Lock()
	s.operations = append(s.operations, operation)
	s.mu.Unlock()
}

func (s *recordingLifecycleStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.operations)
}

func (s *recordingLifecycleStore) reset() {
	s.mu.Lock()
	s.operations = nil
	s.mu.Unlock()
}

func (s *recordingLifecycleStore) unblockSave() {
	if s.saveRelease != nil {
		select {
		case <-s.saveRelease:
		default:
			close(s.saveRelease)
		}
	}
}

type lifecycleFixture struct {
	client    *pkceflow.Client
	flow      *scriptedLifecycleFlow
	store     *recordingLifecycleStore
	emitter   *oidctest.RecordingEmitter
	transport *authorizationCodeTransport
}

func newLifecycleFixture(
	t *testing.T,
	ignoreCancellation bool,
	gateTokenResponse bool,
) *lifecycleFixture {
	t.Helper()
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(lifecycleRedirectURI),
		oidctest.WithAccessTTL(5*time.Minute),
	)
	flow := newScriptedLifecycleFlow(idp, ignoreCancellation)
	store := newRecordingLifecycleStore()
	emitter := &oidctest.RecordingEmitter{}
	transport := newAuthorizationCodeTransport(gateTokenResponse)
	t.Cleanup(transport.unblock)

	client, err := pkceflow.New(
		pkceflow.Config{IssuerURL: idp.IssuerURL(), ClientID: "test-app"},
		flow,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
		pkceflow.WithHTTPClient(&http.Client{Transport: transport}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return &lifecycleFixture{
		client:    client,
		flow:      flow,
		store:     store,
		emitter:   emitter,
		transport: transport,
	}
}

func nextLifecycleCall(
	t *testing.T,
	flow *scriptedLifecycleFlow,
	kind string,
) *scriptedLifecycleCall {
	t.Helper()
	select {
	case call := <-flow.calls:
		if call.kind != kind {
			t.Fatalf("flow call kind = %q, want %q", call.kind, kind)
		}
		return call
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s flow", kind)
		return nil
	}
}

func waitLifecycleError(t *testing.T, result <-chan error, message string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return nil
	}
}

func waitLifecycleSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func lifecycleEventNames(emitter *oidctest.RecordingEmitter) []string {
	events := emitter.Events()
	names := make([]string, 0, len(events))
	for _, event := range events {
		names = append(names, event.Name)
	}
	return names
}

func completeLifecycleLogin(t *testing.T, fixture *lifecycleFixture) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fixture.client.Login(context.Background()) }()
	call := nextLifecycleCall(t, fixture.flow, "login")
	call.release()
	if err := waitLifecycleError(t, done, "Login did not finish"); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

func TestLatestLoginSupersedesWaitingLogin(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	firstDone := make(chan error, 1)
	go func() { firstDone <- fixture.client.Login(context.Background()) }()
	firstCall := nextLifecycleCall(t, fixture.flow, "login")

	secondDone := make(chan error, 1)
	go func() { secondDone <- fixture.client.Login(context.Background()) }()
	waitLifecycleSignal(t, firstCall.ctx.Done(), "new Login did not cancel the old flow")
	firstCall.release()
	if err := waitLifecycleError(t, firstDone, "superseded Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("superseded Login error = %v, want ErrFlowCancelled", err)
	}

	secondCall := nextLifecycleCall(t, fixture.flow, "login")
	secondCall.release()
	if err := waitLifecycleError(t, secondDone, "winning Login did not finish"); err != nil {
		t.Fatalf("winning Login: %v", err)
	}

	if got := fixture.flow.maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent browser flows = %d, want 1", got)
	}
	if got := fixture.transport.requests.Load(); got != 1 {
		t.Fatalf("authorization-code exchanges = %d, want 1", got)
	}
	if got, want := fixture.store.snapshot(), []string{"save"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedIn}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestThirdLoginSupersedesPermitWaiter(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	firstDone := make(chan error, 1)
	go func() { firstDone <- fixture.client.Login(context.Background()) }()
	firstCall := nextLifecycleCall(t, fixture.flow, "login")

	secondDone := make(chan error, 1)
	go func() { secondDone <- fixture.client.Login(context.Background()) }()
	waitLifecycleSignal(t, firstCall.ctx.Done(), "second Login was not admitted")

	thirdDone := make(chan error, 1)
	go func() { thirdDone <- fixture.client.Login(context.Background()) }()
	if err := waitLifecycleError(t, secondDone, "middle Login did not leave the permit queue"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("middle Login error = %v, want ErrFlowCancelled", err)
	}
	firstCall.release()
	if err := waitLifecycleError(t, firstDone, "first Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("first Login error = %v, want ErrFlowCancelled", err)
	}

	thirdCall := nextLifecycleCall(t, fixture.flow, "login")
	thirdCall.release()
	if err := waitLifecycleError(t, thirdDone, "third Login did not finish"); err != nil {
		t.Fatalf("third Login: %v", err)
	}
	if got := fixture.transport.requests.Load(); got != 1 {
		t.Fatalf("authorization-code exchanges = %d, want 1", got)
	}
	if got := fixture.flow.maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent browser flows = %d, want 1", got)
	}
}

func TestPreCancelledLoginDoesNotSupersedeActiveLogin(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	activeDone := make(chan error, 1)
	go func() { activeDone <- fixture.client.Login(context.Background()) }()
	activeCall := nextLifecycleCall(t, fixture.flow, "login")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.client.Login(cancelled); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("pre-cancelled Login error = %v, want ErrFlowCancelled", err)
	}
	select {
	case <-activeCall.ctx.Done():
		t.Fatal("pre-cancelled Login superseded the active Login")
	default:
	}

	activeCall.release()
	if err := waitLifecycleError(t, activeDone, "active Login did not finish"); err != nil {
		t.Fatalf("active Login: %v", err)
	}
}

func TestLogoutPreventsLateLoginCallbackCommit(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	loginDone := make(chan error, 1)
	go func() { loginDone <- fixture.client.Login(context.Background()) }()
	loginCall := nextLifecycleCall(t, fixture.flow, "login")

	if err := fixture.client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	waitLifecycleSignal(t, loginCall.ctx.Done(), "Logout did not cancel Login")
	if got := fixture.transport.requests.Load(); got != 0 {
		t.Fatalf("authorization-code exchanges before late callback = %d, want 0", got)
	}
	loginCall.release()
	if err := waitLifecycleError(t, loginDone, "late Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("late Login error = %v, want ErrFlowCancelled", err)
	}

	state, err := fixture.store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.IsZero() || fixture.client.AuthStatus().CanUseApp {
		t.Fatalf("late Login resurrected state: %+v", state)
	}
	if got, want := fixture.store.snapshot(), []string{"delete"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestLogoutSuppressesConsumedLateTokenResponse(t *testing.T) {
	fixture := newLifecycleFixture(t, false, true)
	loginDone := make(chan error, 1)
	go func() { loginDone <- fixture.client.Login(context.Background()) }()
	loginCall := nextLifecycleCall(t, fixture.flow, "login")
	loginCall.release()
	waitLifecycleSignal(t, fixture.transport.entered, "token exchange did not reach response gate")

	if err := fixture.client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	fixture.transport.unblock()
	if err := waitLifecycleError(t, loginDone, "late token response Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("late token response error = %v, want ErrFlowCancelled", err)
	}

	state, err := fixture.store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.IsZero() {
		t.Fatalf("late token response persisted state: %+v", state)
	}
	if got, want := fixture.store.snapshot(), []string{"delete"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestLatestLoginSuppressesConsumedOlderTokenResponse(t *testing.T) {
	fixture := newLifecycleFixture(t, false, true)
	firstDone := make(chan error, 1)
	go func() { firstDone <- fixture.client.Login(context.Background()) }()
	nextLifecycleCall(t, fixture.flow, "login").release()
	waitLifecycleSignal(t, fixture.transport.entered, "first token exchange did not reach response gate")

	secondDone := make(chan error, 1)
	go func() { secondDone <- fixture.client.Login(context.Background()) }()
	nextLifecycleCall(t, fixture.flow, "login").release()
	if err := waitLifecycleError(t, secondDone, "winning Login did not finish"); err != nil {
		t.Fatalf("winning Login: %v", err)
	}

	fixture.transport.unblock()
	if err := waitLifecycleError(t, firstDone, "superseded token response Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("superseded token response error = %v, want ErrFlowCancelled", err)
	}
	if got := fixture.transport.requests.Load(); got != 2 {
		t.Fatalf("authorization-code exchanges = %d, want 2", got)
	}
	if got, want := fixture.store.snapshot(), []string{"save"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedIn}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestLoginSupersedesPendingRPLogout(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	completeLifecycleLogin(t, fixture)
	fixture.store.reset()
	fixture.emitter.Reset()
	fixture.transport.requests.Store(0)

	logoutDone := make(chan error, 1)
	go func() { logoutDone <- fixture.client.Logout(context.Background()) }()
	logoutCall := nextLifecycleCall(t, fixture.flow, "logout")
	if fixture.client.AuthStatus().CanUseApp {
		t.Fatal("Logout did not clear local state before the RP flow")
	}

	loginDone := make(chan error, 1)
	go func() { loginDone <- fixture.client.Login(context.Background()) }()
	waitLifecycleSignal(t, logoutCall.ctx.Done(), "new Login did not cancel RP logout")
	logoutCall.release()
	if err := waitLifecycleError(t, logoutDone, "RP Logout did not finish"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	loginCall := nextLifecycleCall(t, fixture.flow, "login")
	loginCall.release()
	if err := waitLifecycleError(t, loginDone, "replacement Login did not finish"); err != nil {
		t.Fatalf("replacement Login: %v", err)
	}

	if got := fixture.flow.maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent browser flows = %d, want 1", got)
	}
	if got, want := fixture.store.snapshot(), []string{"delete", "save"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedOut, pkceflow.EventLoggedIn}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if !fixture.client.AuthStatus().Valid {
		t.Fatal("replacement Login did not establish the final session")
	}
}

func TestConcurrentLogoutCoalesces(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	completeLifecycleLogin(t, fixture)
	fixture.store.reset()
	fixture.emitter.Reset()

	firstDone := make(chan error, 1)
	go func() { firstDone <- fixture.client.Logout(context.Background()) }()
	firstCall := nextLifecycleCall(t, fixture.flow, "logout")

	if err := fixture.client.Logout(context.Background()); err != nil {
		t.Fatalf("coalesced Logout: %v", err)
	}
	select {
	case <-firstCall.ctx.Done():
		t.Fatal("coalesced Logout cancelled the active RP flow")
	default:
	}
	firstCall.release()
	if err := waitLifecycleError(t, firstDone, "active Logout did not finish"); err != nil {
		t.Fatalf("active Logout: %v", err)
	}

	if got, want := fixture.store.snapshot(), []string{"delete"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestPreCancelledLogoutClearsLocallyWithoutBrowserFlow(t *testing.T) {
	fixture := newLifecycleFixture(t, false, false)
	completeLifecycleLogin(t, fixture)
	fixture.store.reset()
	fixture.emitter.Reset()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.client.Logout(ctx); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	select {
	case call := <-fixture.flow.calls:
		call.release()
		t.Fatalf("pre-cancelled Logout unexpectedly started a %s browser flow", call.kind)
	default:
	}
	state, err := fixture.store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.IsZero() || fixture.client.AuthStatus().CanUseApp {
		t.Fatalf("pre-cancelled Logout left authenticated state: %+v", state)
	}
	if got, want := fixture.store.snapshot(), []string{"delete"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(fixture.emitter), []string{pkceflow.EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

type leakingLogoutFlow struct {
	inner       *oidctest.FakeFlowHandler
	redirectURI string
}

func (f *leakingLogoutFlow) RedirectURI() string {
	return f.redirectURI
}

func (f *leakingLogoutFlow) PostLogoutRedirectURI() string {
	return f.redirectURI
}

func (f *leakingLogoutFlow) StartAuthFlow(
	ctx context.Context,
	authURL string,
) (string, error) {
	return f.inner.StartAuthFlow(ctx, authURL)
}

func (f *leakingLogoutFlow) StartLogoutFlow(
	_ context.Context,
	logoutURL string,
) (string, error) {
	return "", fmt.Errorf("handler echoed logout URL: %s", logoutURL)
}

func TestLogoutHandlerErrorDoesNotLeakLogoutURL(t *testing.T) {
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(lifecycleRedirectURI),
	)
	flow := &leakingLogoutFlow{
		inner:       oidctest.NewFakeFlowHandler(idp, lifecycleRedirectURI),
		redirectURI: lifecycleRedirectURI,
	}
	store := &oidctest.MemoryStore{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	client, err := pkceflow.New(
		pkceflow.Config{IssuerURL: idp.IssuerURL(), ClientID: "test-app"},
		flow,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	logs.Reset()

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	output := logs.String()
	if !strings.Contains(output, "RP-Initiated Logout flow failed") {
		t.Fatalf("logout log = %q, want fixed failure message", output)
	}
	for _, secret := range []string{state.IDToken, "id_token_hint", "/end_session", "handler echoed logout URL"} {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatalf("logout log contains sensitive URL material %q: %q", secret, output)
		}
	}
}

type reentrantLoginEmitter struct {
	mu          sync.Mutex
	events      []string
	client      *pkceflow.Client
	loginResult chan error
	once        sync.Once
}

func (e *reentrantLoginEmitter) Emit(event string, _ any) {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()
	if event == pkceflow.EventLoggedOut {
		e.once.Do(func() {
			e.loginResult <- e.client.Login(context.Background())
		})
	}
}

func (e *reentrantLoginEmitter) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.events)
}

func TestLoggedOutEmitterCanReenterLoginBeforeRPFlow(t *testing.T) {
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(lifecycleRedirectURI),
	)
	flow := newScriptedLifecycleFlow(idp, false)
	store := newRecordingLifecycleStore()
	emitter := &reentrantLoginEmitter{loginResult: make(chan error, 1)}
	client, err := pkceflow.New(
		pkceflow.Config{IssuerURL: idp.IssuerURL(), ClientID: "test-app"},
		flow,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	emitter.client = client
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	initialDone := make(chan error, 1)
	go func() { initialDone <- client.Login(context.Background()) }()
	nextLifecycleCall(t, flow, "login").release()
	if err := waitLifecycleError(t, initialDone, "initial Login did not finish"); err != nil {
		t.Fatalf("initial Login: %v", err)
	}
	emitter.mu.Lock()
	emitter.events = nil
	emitter.mu.Unlock()
	store.reset()

	logoutDone := make(chan error, 1)
	go func() { logoutDone <- client.Logout(context.Background()) }()
	reentrantCall := nextLifecycleCall(t, flow, "login")
	reentrantCall.release()
	if err := waitLifecycleError(t, emitter.loginResult, "reentrant Login did not finish"); err != nil {
		t.Fatalf("reentrant Login: %v", err)
	}
	if err := waitLifecycleError(t, logoutDone, "Logout did not finish"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	select {
	case call := <-flow.calls:
		call.release()
		t.Fatalf("stale Logout unexpectedly started a %s browser flow", call.kind)
	default:
	}
	if got, want := emitter.snapshot(), []string{pkceflow.EventLoggedOut, pkceflow.EventLoggedIn}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if got, want := store.snapshot(), []string{"delete", "save"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
}

func TestLoginCommitBeforeLogoutStaysOrdered(t *testing.T) {
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(lifecycleRedirectURI),
	)
	flow := newScriptedLifecycleFlow(idp, false)
	store := newBlockingLifecycleStore()
	t.Cleanup(store.unblockSave)
	emitter := &oidctest.RecordingEmitter{}
	client, err := pkceflow.New(
		pkceflow.Config{IssuerURL: idp.IssuerURL(), ClientID: "test-app"},
		flow,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	loginDone := make(chan error, 1)
	go func() { loginDone <- client.Login(context.Background()) }()
	nextLifecycleCall(t, flow, "login").release()
	waitLifecycleSignal(t, store.saveEntered, "Login did not reach blocked Save")

	logoutDone := make(chan error, 1)
	go func() { logoutDone <- client.Logout(context.Background()) }()
	store.unblockSave()
	if err := waitLifecycleError(t, loginDone, "Login did not finish after Save release"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	nextLifecycleCall(t, flow, "logout").release()
	if err := waitLifecycleError(t, logoutDone, "Logout did not finish after Login commit"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.IsZero() {
		t.Fatalf("final persisted state = %+v, want zero", state)
	}
	if got, want := store.snapshot(), []string{"save", "delete"}; !slices.Equal(got, want) {
		t.Fatalf("persistence operations = %v, want %v", got, want)
	}
	if got, want := lifecycleEventNames(emitter), []string{pkceflow.EventLoggedIn, pkceflow.EventLoggedOut}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestCallerCancellationStopsLogin(t *testing.T) {
	fixture := newLifecycleFixture(t, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	loginDone := make(chan error, 1)
	go func() { loginDone <- fixture.client.Login(ctx) }()
	call := nextLifecycleCall(t, fixture.flow, "login")
	deadline, ok := call.ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
		t.Fatalf("flow deadline = %v, want active configured LoginTimeout", deadline)
	}
	cancel()

	if err := waitLifecycleError(t, loginDone, "cancelled Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("cancelled Login error = %v, want ErrFlowCancelled", err)
	}
	if got := fixture.transport.requests.Load(); got != 0 {
		t.Fatalf("authorization-code exchanges = %d, want 0", got)
	}
	if got := fixture.store.snapshot(); len(got) != 0 {
		t.Fatalf("persistence operations = %v, want none", got)
	}
	if got := lifecycleEventNames(fixture.emitter); len(got) != 0 {
		t.Fatalf("events = %v, want none", got)
	}
}

func TestCallerCancellationRejectsLateCallback(t *testing.T) {
	fixture := newLifecycleFixture(t, true, false)
	ctx, cancel := context.WithCancel(context.Background())
	loginDone := make(chan error, 1)
	go func() { loginDone <- fixture.client.Login(ctx) }()
	call := nextLifecycleCall(t, fixture.flow, "login")
	cancel()
	waitLifecycleSignal(t, call.ctx.Done(), "caller cancellation did not reach flow handler")
	call.release()

	if err := waitLifecycleError(t, loginDone, "late callback Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("late callback Login error = %v, want ErrFlowCancelled", err)
	}
	if got := fixture.transport.requests.Load(); got != 0 {
		t.Fatalf("authorization-code exchanges = %d, want 0", got)
	}
	if got := fixture.store.snapshot(); len(got) != 0 {
		t.Fatalf("persistence operations = %v, want none", got)
	}
	if got := lifecycleEventNames(fixture.emitter); len(got) != 0 {
		t.Fatalf("events = %v, want none", got)
	}
}

func TestCallerCancellationSuppressesConsumedTokenResponse(t *testing.T) {
	fixture := newLifecycleFixture(t, false, true)
	ctx, cancel := context.WithCancel(context.Background())
	loginDone := make(chan error, 1)
	go func() { loginDone <- fixture.client.Login(ctx) }()
	nextLifecycleCall(t, fixture.flow, "login").release()
	waitLifecycleSignal(t, fixture.transport.entered, "token exchange did not reach response gate")

	cancel()
	fixture.transport.unblock()
	if err := waitLifecycleError(t, loginDone, "cancelled token response Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("cancelled token response error = %v, want ErrFlowCancelled", err)
	}
	state, err := fixture.store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.IsZero() {
		t.Fatalf("cancelled token response persisted state: %+v", state)
	}
	if got := fixture.store.snapshot(); len(got) != 0 {
		t.Fatalf("persistence operations = %v, want none", got)
	}
	if got := lifecycleEventNames(fixture.emitter); len(got) != 0 {
		t.Fatalf("events = %v, want none", got)
	}
}

func TestIndependentClientsKeepIndependentBrowserPermits(t *testing.T) {
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(lifecycleRedirectURI),
	)
	flow := newScriptedLifecycleFlow(idp, true)
	clients := make([]*pkceflow.Client, 2)
	for index := range clients {
		client, err := pkceflow.New(
			pkceflow.Config{IssuerURL: idp.IssuerURL(), ClientID: "test-app"},
			flow,
			pkceflow.WithTokenPersistence(&oidctest.MemoryStore{}),
		)
		if err != nil {
			t.Fatalf("New client %d: %v", index, err)
		}
		if err := client.Init(context.Background()); err != nil {
			t.Fatalf("Init client %d: %v", index, err)
		}
		clients[index] = client
	}

	results := make(chan error, len(clients))
	for _, client := range clients {
		go func() { results <- client.Login(context.Background()) }()
	}
	first := nextLifecycleCall(t, flow, "login")
	second := nextLifecycleCall(t, flow, "login")
	if got := flow.active.Load(); got != 2 {
		t.Fatalf("active independent browser flows = %d, want 2", got)
	}
	first.release()
	second.release()
	for range clients {
		if err := waitLifecycleError(t, results, "independent Login did not finish"); err != nil {
			t.Fatalf("independent Login: %v", err)
		}
	}
	if got := flow.maxActive.Load(); got != 2 {
		t.Fatalf("maximum independent browser flows = %d, want 2", got)
	}
}

func TestMobileFlowReplacementIgnoresLateOldCallback(t *testing.T) {
	const redirectURI = "com.example.app://auth/callback"
	idp := oidctest.NewFakeIDP(t,
		oidctest.WithClientID("test-app"),
		oidctest.WithRedirectURI(redirectURI),
	)
	opened := make(chan string, 2)
	flow := mobileflow.New(redirectURI, func(authURL string) error {
		opened <- authURL
		return nil
	})
	store := &oidctest.MemoryStore{}
	emitter := &oidctest.RecordingEmitter{}
	client, err := pkceflow.New(
		pkceflow.Config{IssuerURL: idp.IssuerURL(), ClientID: "test-app"},
		flow,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithEventEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- client.Login(context.Background()) }()
	firstURL := waitOpenedURL(t, opened, "first mobile Login did not open a URL")

	secondDone := make(chan error, 1)
	go func() { secondDone <- client.Login(context.Background()) }()
	if err := waitLifecycleError(t, firstDone, "superseded mobile Login did not finish"); !errors.Is(err, pkceflow.ErrFlowCancelled) {
		t.Fatalf("superseded mobile Login error = %v, want ErrFlowCancelled", err)
	}
	secondURL := waitOpenedURL(t, opened, "replacement mobile Login did not open a URL")

	flow.DeliverURL(fetchAuthorizationCallback(t, firstURL))
	select {
	case err := <-secondDone:
		t.Fatalf("late old callback completed replacement Login: %v", err)
	default:
	}
	flow.DeliverURL(fetchAuthorizationCallback(t, secondURL))
	if err := waitLifecycleError(t, secondDone, "replacement mobile Login did not finish"); err != nil {
		t.Fatalf("replacement mobile Login: %v", err)
	}
	if got, want := lifecycleEventNames(emitter), []string{pkceflow.EventLoggedIn}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func waitOpenedURL(t *testing.T, opened <-chan string, message string) string {
	t.Helper()
	select {
	case target := <-opened:
		return target
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return ""
	}
}

func fetchAuthorizationCallback(t *testing.T, authURL string) string {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, http.NoBody)
	if err != nil {
		t.Fatalf("build authorization request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("authorization request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorization status = %d, want %d", response.StatusCode, http.StatusFound)
	}
	callback := response.Header.Get("Location")
	if callback == "" {
		t.Fatal("authorization response missing callback Location")
	}
	return callback
}
