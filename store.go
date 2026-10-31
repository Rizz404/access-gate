package main

import (
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS sites (
	id      INTEGER PRIMARY KEY,
	name    TEXT NOT NULL UNIQUE,
	enabled INTEGER NOT NULL DEFAULT 1,
	upstream TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS entries (
	id         INTEGER PRIMARY KEY,
	site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	cidr       TEXT NOT NULL,
	label      TEXT NOT NULL DEFAULT '',
	expires_at INTEGER,
	created_at INTEGER NOT NULL,
	UNIQUE(site_id, cidr)
);
CREATE TABLE IF NOT EXISTS denied (
	id   INTEGER PRIMARY KEY,
	ts   INTEGER NOT NULL,
	site TEXT NOT NULL,
	ip   TEXT NOT NULL
);`

type Site struct {
	ID       int64
	Name     string
	Enabled  bool
	Upstream string // proxy mode target (http://host:port); empty = /auth mode only
}

type Entry struct {
	ID        int64
	CIDR      string
	Label     string
	ExpiresAt *time.Time
}

type Denied struct {
	TS   time.Time
	Site string
	IP   string
}

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// migrate DBs created before proxy mode existed; "duplicate column" means already migrated.
	if _, err := db.Exec(`ALTER TABLE sites ADD COLUMN upstream TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// AddSite creates a site; upstream is optional and only needed for proxy mode.
func (s *Store) AddSite(name, upstream string) error {
	if name == "" {
		return errors.New("nama situs kosong")
	}
	if upstream != "" {
		u, err := url.Parse(upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("upstream harus berupa URL http(s)://host[:port]")
		}
	}
	_, err := s.db.Exec(`INSERT INTO sites(name, upstream) VALUES(?,?)`, name, upstream)
	return err
}

// Upstream returns the proxy target of an enabled site ("" if unknown, disabled, or not set).
func (s *Store) Upstream(site string) (string, error) {
	var u string
	err := s.db.QueryRow(`SELECT upstream FROM sites WHERE name=? AND enabled=1`, site).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return u, err
}

func (s *Store) DeleteSite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *Store) SetSiteEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE sites SET enabled=? WHERE id=?`, enabled, id)
	return err
}

func (s *Store) ListSites() ([]Site, error) {
	rows, err := s.db.Query(`SELECT id, name, enabled, upstream FROM sites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		var x Site
		if err := rows.Scan(&x.ID, &x.Name, &x.Enabled, &x.Upstream); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// AddEntry stores a normalized CIDR; re-adding an existing CIDR refreshes label and expiry.
func (s *Store) AddEntry(siteID int64, cidr, label string, expires *time.Time) error {
	p, err := ParseCIDR(cidr)
	if err != nil {
		return err
	}
	var exp any
	if expires != nil {
		exp = expires.Unix()
	}
	_, err = s.db.Exec(`INSERT INTO entries(site_id, cidr, label, expires_at, created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(site_id, cidr) DO UPDATE SET label=excluded.label, expires_at=excluded.expires_at`,
		siteID, p.String(), label, exp, time.Now().Unix())
	return err
}

func (s *Store) DeleteEntry(id int64) error {
	_, err := s.db.Exec(`DELETE FROM entries WHERE id=?`, id)
	return err
}

func (s *Store) ListEntries(siteID int64) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT id, cidr, label, expires_at FROM entries WHERE site_id=? ORDER BY id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var exp sql.NullInt64
		if err := rows.Scan(&e.ID, &e.CIDR, &e.Label, &exp); err != nil {
			return nil, err
		}
		if exp.Valid {
			t := time.Unix(exp.Int64, 0)
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// activeCIDRs returns non-expired CIDRs of an enabled site; unknown or disabled site -> none.
// shortcut: queries SQLite on every call (no cache), upgrade if /auth latency or load matters.
func (s *Store) activeCIDRs(site string, now time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT e.cidr FROM entries e JOIN sites st ON st.id=e.site_id
		WHERE st.name=? AND st.enabled=1 AND (e.expires_at IS NULL OR e.expires_at>?)`, site, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const deniedKeep = 200

func (s *Store) LogDenied(site, ip string, now time.Time) error {
	if _, err := s.db.Exec(`INSERT INTO denied(ts, site, ip) VALUES(?,?,?)`, now.Unix(), site, ip); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM denied WHERE id <= (SELECT MAX(id) FROM denied) - ?`, deniedKeep)
	return err
}

func (s *Store) RecentDenied(n int) ([]Denied, error) {
	rows, err := s.db.Query(`SELECT ts, site, ip FROM denied ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Denied
	for rows.Next() {
		var d Denied
		var ts int64
		if err := rows.Scan(&ts, &d.Site, &d.IP); err != nil {
			return nil, err
		}
		d.TS = time.Unix(ts, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}
