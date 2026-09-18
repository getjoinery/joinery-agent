package primitives

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
)

// A minimal database/sql driver for tests: canned answers by query text, no
// network, no dependency. It answers only what the tests under this package
// ask; anything else is an error the caller sees.

type fakeRows struct {
	columns []string
	rows    [][]driver.Value
}

type fakeDriver struct {
	mu      sync.Mutex
	answers map[string]fakeRows // keyed by a substring of the query
	err     error               // when set, every query fails with it
}

func (d *fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{d: d}, nil }

type fakeConn struct{ d *fakeDriver }

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeStmt{c: c, query: query}, nil
}
func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions") }

type fakeStmt struct {
	c     *fakeConn
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("read-only fake")
}
func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	if s.c.d.err != nil {
		return nil, s.c.d.err
	}
	for key, answer := range s.c.d.answers {
		if strings.Contains(s.query, key) {
			rows := answer.rows
			// Honour a LIMIT $1 the way the real database would.
			if len(args) == 1 {
				if n, ok := args[0].(int64); ok && int(n) < len(rows) {
					rows = rows[:n]
				}
			}
			return &fakeResult{columns: answer.columns, rows: rows}, nil
		}
	}
	return nil, errors.New("fake database has no answer for: " + s.query)
}

type fakeResult struct {
	columns []string
	rows    [][]driver.Value
	i       int
}

func (r *fakeResult) Columns() []string { return r.columns }
func (r *fakeResult) Close() error      { return nil }
func (r *fakeResult) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}

var (
	fakeDriverOnce sync.Once
	fakeDriverInst = &fakeDriver{answers: map[string]fakeRows{}}
)

// fakeDB returns a DBProvider whose database answers the given queries. One
// driver is registered for the process; each call replaces its answers, so
// tests that use it must not run in parallel with each other.
func fakeDB(answers map[string]fakeRows, err error) DBProvider {
	fakeDriverOnce.Do(func() { sql.Register("joinery-fake", fakeDriverInst) })
	fakeDriverInst.mu.Lock()
	fakeDriverInst.answers = answers
	fakeDriverInst.err = err
	fakeDriverInst.mu.Unlock()
	return func() (*sql.DB, error) { return sql.Open("joinery-fake", "") }
}

// settingAnswer is the one-row answer to the agent_log_access setting read.
func settingAnswer(value string) map[string]fakeRows {
	return map[string]fakeRows{
		"FROM stg_settings WHERE stg_name = $1": {
			columns: []string{"stg_value"},
			rows:    [][]driver.Value{{value}},
		},
	}
}

var _ = context.Background
