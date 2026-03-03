// Package storage persists AgentSentry scan results to a SQLite database.
// It uses modernc.org/sqlite — a pure-Go driver with no CGo dependency,
// making cross-compilation (linux/darwin/windows) straightforward.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

const schema = `
CREATE TABLE IF NOT EXISTS scan_results (
    id          TEXT     PRIMARY KEY,
    tool_name   TEXT     NOT NULL,
    protocol    TEXT     NOT NULL,
    risk_score  INTEGER  NOT NULL,
    grade       TEXT     NOT NULL,
    findings    TEXT     NOT NULL,  -- JSON array of model.Issue
    scanned_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_results_tool_name ON scan_results(tool_name);
CREATE INDEX IF NOT EXISTS idx_scan_results_grade     ON scan_results(grade);
`

// ScanRecord is the persisted form of a single tool scan.
type ScanRecord struct {
	ID        string
	ToolName  string
	Protocol  model.ProtocolType
	RiskScore int
	Grade     model.Grade
	Findings  []model.Issue
	ScannedAt time.Time
}

// Store wraps a SQLite connection and exposes scan-result persistence.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at dsn and runs the schema
// migration.  Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	return OpenContext(context.Background(), dsn)
}

// OpenContext is like Open but accepts an explicit context for the schema migration.
func OpenContext(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open db: %w", err)
	}
	if _, err = db.ExecContext(ctx, schema); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("storage: migrate schema: %w (also failed to close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("storage: migrate schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("storage: close db: %w", err)
	}
	return nil
}

// Save persists a ScanRecord.  If a record with the same ID already exists it
// is replaced.
func (s *Store) Save(ctx context.Context, r ScanRecord) error {
	findings, err := json.Marshal(r.Findings)
	if err != nil {
		return fmt.Errorf("storage: marshal findings: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO scan_results
			(id, tool_name, protocol, risk_score, grade, findings, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ToolName, string(r.Protocol),
		r.RiskScore, string(r.Grade),
		string(findings), r.ScannedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("storage: save scan result: %w", err)
	}
	return nil
}

// Get retrieves a single ScanRecord by ID.  Returns sql.ErrNoRows if not found.
func (s *Store) Get(ctx context.Context, id string) (ScanRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tool_name, protocol, risk_score, grade, findings, scanned_at
		FROM scan_results WHERE id = ?`, id)
	return scanRow(row)
}

// ListByGrade returns all scan records with the given grade, newest first.
func (s *Store) ListByGrade(ctx context.Context, grade model.Grade) ([]ScanRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tool_name, protocol, risk_score, grade, findings, scanned_at
		FROM scan_results WHERE grade = ? ORDER BY scanned_at DESC`, string(grade))
	if err != nil {
		return nil, fmt.Errorf("storage: list by grade: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			// rows.Close error is superseded by rows.Err checked below
			_ = closeErr
		}
	}()

	var records []ScanRecord
	for rows.Next() {
		r, rowErr := scanRow(rows)
		if rowErr != nil {
			return nil, rowErr
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate rows: %w", err)
	}
	return records, nil
}

// Count returns the total number of stored scan records.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_results`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("storage: count: %w", err)
	}
	return n, nil
}

// scanner abstracts *sql.Row and *sql.Rows for scanRow.
type scanner interface {
	Scan(dest ...any) error
}

func scanRow(s scanner) (ScanRecord, error) {
	var (
		r            ScanRecord
		protocol     string
		grade        string
		findingsJSON string
		scannedAt    time.Time
	)
	if err := s.Scan(&r.ID, &r.ToolName, &protocol, &r.RiskScore, &grade, &findingsJSON, &scannedAt); err != nil {
		return ScanRecord{}, fmt.Errorf("storage: %w", err) // wraps sql.ErrNoRows so callers can use errors.Is
	}
	r.Protocol = model.ProtocolType(protocol)
	r.Grade = model.Grade(grade)
	r.ScannedAt = scannedAt

	if err := json.Unmarshal([]byte(findingsJSON), &r.Findings); err != nil {
		return ScanRecord{}, fmt.Errorf("storage: unmarshal findings: %w", err)
	}
	return r, nil
}
