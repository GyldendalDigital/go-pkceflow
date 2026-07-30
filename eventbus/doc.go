// Package eventbus provides event bus utilities for go-pkceflow.
//
// DeferredEventBus buffers events until a target EventEmitter is set,
// then flushes buffered events and switches to direct emission. This solves
// startup ordering issues where auth events are emitted before the UI
// framework is ready to receive them (e.g., Wails service creation before app).
//
// NoopEventBus silently drops all events and is useful for explicit
// headless/CLI wiring. The core client uses its own internal no-op emitter when
// no EventEmitter option is supplied.
package eventbus
