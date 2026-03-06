package pwsh

import (
	"runtime"
	"sync"
)

// defaultPoolSize is the number of pwsh workers to keep ready.
// Capped at 4: each worker is a full pwsh subprocess (~50 MB RSS + JIT warm-up).
const defaultPoolSize = 4

// WorkerPool holds a fixed set of pwsh Worker subprocesses.
// Callers acquire a worker for the duration of one Parse() call and return it
// immediately after, allowing N concurrent parses with N workers.
type WorkerPool struct {
	workers chan *Worker
}

// NewWorkerPool creates a pool of size workers, all pointing to pwshPath.
// size <= 0 uses min(GOMAXPROCS, defaultPoolSize).
func NewWorkerPool(pwshPath string, size int) (*WorkerPool, error) {
	if size <= 0 {
		size = min(runtime.GOMAXPROCS(0), defaultPoolSize)
	}
	workers := make([]*Worker, size)
	for i := range size {
		w, err := NewWorker(pwshPath)
		if err != nil {
			for _, w := range workers[:i] {
				w.Stop()
			}
			return nil, err
		}
		workers[i] = w
	}

	// Warm up all workers concurrently: each sends a trivial parse so the
	// pwsh process initialises its bootstrap script and JIT-compiles the hot
	// path before any real test or production parse arrives. Without warmup,
	// workers that lose the CPU lottery during parallel startup can still be
	// cold when first acquired, triggering the 30 s parseTimeout on slow CI
	// runners. Warmup errors are intentionally ignored — a failed warmup kills
	// the worker (proc=nil) so Worker.Parse() will restart it automatically.
	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Add(1)
		go func(w *Worker) {
			defer wg.Done()
			w.Parse("$null") //nolint:errcheck // warmup only; restart handled by Parse()
		}(w)
	}
	wg.Wait()

	ch := make(chan *Worker, size)
	for _, w := range workers {
		ch <- w
	}
	return &WorkerPool{workers: ch}, nil
}

// Parse acquires an idle worker, delegates the parse, then returns the worker.
// Blocks if all workers are busy. Safe for concurrent use.
func (p *WorkerPool) Parse(cmd string) (Response, error) {
	w := <-p.workers
	defer func() { p.workers <- w }()
	return w.Parse(cmd)
}

// Stop waits for all in-flight Parse calls to complete, then shuts down every
// worker. Must not be called concurrently with itself.
func (p *WorkerPool) Stop() {
	for range cap(p.workers) {
		w := <-p.workers
		w.Stop()
	}
}
