package postgres

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// bloatRefreshInterval bounds how often the heavy ioguix queries run.
// Bloat changes slowly — 15 min is plenty for dashboards and doesn't churn
// the scrape budget. Queries are ~100–400 ms warm on a medium-sized cluster.
const bloatRefreshInterval = 15 * time.Minute

// topBloatN caps how many rows each ioguix query returns. Must match the
// LIMIT clause in scanTableBloat/scanIndexBloat. 50 is enough to highlight
// the worst offenders without inflating Prometheus cardinality (50 × 4
// series per database).
const topBloatN = 50

// bloatRetryNow is the sentinel we write into bloatLastRefresh when both
// scans failed, so tryBeginBloatRefresh reports stale on the next scrape
// and kicks another attempt immediately instead of waiting 15 min.
var bloatRetryNow = time.Time{}

type tableBloatEntry struct {
	schema string
	table  string
	size   int64
	pct    float64
}

type indexBloatEntry struct {
	schema string
	table  string
	index  string
	size   int64
	pct    float64
}

// tryBeginBloatRefresh is a stampede barrier: the first caller past the
// staleness check takes ownership by bumping bloatLastRefresh to now, so
// concurrent scrapes see a fresh cache and skip their own refresh. Returns
// true only to the owner.
func (c *Collector) tryBeginBloatRefresh(now time.Time) bool {
	c.bloatMu.Lock()
	defer c.bloatMu.Unlock()
	if now.Sub(c.bloatLastRefresh) <= bloatRefreshInterval {
		return false
	}
	c.bloatLastRefresh = now
	return true
}

func (c *Collector) collectBloat(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.tryBeginBloatRefresh(time.Now()) {
		c.refreshBloat(ctx)
	}

	c.bloatMu.RLock()
	tables := c.bloatTables
	indexes := c.bloatIndexes
	c.bloatMu.RUnlock()

	for _, t := range tables {
		ch <- prometheus.MustNewConstMetric(c.tableBloatSize, prometheus.GaugeValue, float64(t.size), c.database, t.schema, t.table)
		ch <- prometheus.MustNewConstMetric(c.tableBloatPct, prometheus.GaugeValue, t.pct, c.database, t.schema, t.table)
	}
	for _, i := range indexes {
		ch <- prometheus.MustNewConstMetric(c.indexBloatSize, prometheus.GaugeValue, float64(i.size), c.database, i.schema, i.table, i.index)
		ch <- prometheus.MustNewConstMetric(c.indexBloatPct, prometheus.GaugeValue, i.pct, c.database, i.schema, i.table, i.index)
	}
}

// refreshBloat scans tables and indexes concurrently (pool has MaxConns=3,
// queries touch disjoint catalogs). On success the cache is replaced — even
// with zero rows, so after a pg_repack we stop reporting stale bloat. If both
// queries fail we reset the refresh timestamp so the next scrape retries
// instead of waiting a full bloatRefreshInterval on a sick DB.
func (c *Collector) refreshBloat(ctx context.Context) {
	var (
		wg         sync.WaitGroup
		tables     []tableBloatEntry
		indexes    []indexBloatEntry
		tErr, iErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		tables, tErr = c.scanTableBloat(ctx)
	}()
	go func() {
		defer wg.Done()
		indexes, iErr = c.scanIndexBloat(ctx)
	}()
	wg.Wait()

	if tErr != nil {
		c.queryWarn("table_bloat", tErr)
	}
	if iErr != nil {
		c.queryWarn("index_bloat", iErr)
	}

	c.bloatMu.Lock()
	defer c.bloatMu.Unlock()
	if tErr == nil {
		c.bloatTables = tables
	}
	if iErr == nil {
		c.bloatIndexes = indexes
	}
	if tErr != nil && iErr != nil {
		c.bloatLastRefresh = bloatRetryNow
	}
}

// scanTableBloat runs the canonical ioguix table bloat heuristic.
// Source: https://github.com/ioguix/pgsql-bloat-estimation/blob/master/table/table_bloat.sql
// Filters: NOT is_na (tables with `name` type have unreliable estimates),
// bloat_size > 0 (skip healthy tables), top 50 by bloat_size.
func (c *Collector) scanTableBloat(ctx context.Context) ([]tableBloatEntry, error) {
	q := `SELECT schemaname, tblname, bloat_size, bloat_pct FROM (
  SELECT schemaname, tblname,
    CASE WHEN tblpages - est_tblpages_ff > 0
      THEN ((tblpages - est_tblpages_ff) * bs)::bigint
      ELSE 0::bigint END AS bloat_size,
    CASE WHEN tblpages > 0 AND tblpages - est_tblpages_ff > 0
      THEN 100 * (tblpages - est_tblpages_ff) / tblpages::float
      ELSE 0 END AS bloat_pct,
    is_na
  FROM (
    SELECT ceil(reltuples/((bs-page_hdr)/tpl_size)) + ceil(toasttuples/4) AS est_tblpages,
      ceil(reltuples/((bs-page_hdr)*fillfactor/(tpl_size*100))) + ceil(toasttuples/4) AS est_tblpages_ff,
      tblpages, fillfactor, bs, schemaname, tblname, is_na
    FROM (
      SELECT (4 + tpl_hdr_size + tpl_data_size + (2*ma)
          - CASE WHEN tpl_hdr_size%ma = 0 THEN ma ELSE tpl_hdr_size%ma END
          - CASE WHEN ceil(tpl_data_size)::int%ma = 0 THEN ma ELSE ceil(tpl_data_size)::int%ma END
        ) AS tpl_size,
        (heappages + toastpages) AS tblpages, heappages, toastpages, reltuples, toasttuples,
        bs, page_hdr, schemaname, tblname, fillfactor, is_na
      FROM (
        SELECT ns.nspname AS schemaname, tbl.relname AS tblname, tbl.reltuples,
          tbl.relpages AS heappages, coalesce(toast.relpages, 0) AS toastpages,
          coalesce(toast.reltuples, 0) AS toasttuples,
          coalesce(substring(array_to_string(tbl.reloptions, ' ') FROM 'fillfactor=([0-9]+)')::smallint, 100) AS fillfactor,
          current_setting('block_size')::numeric AS bs,
          CASE WHEN version() ~ 'mingw32' OR version() ~ '64-bit|x86_64|ppc64|ia64|amd64' THEN 8 ELSE 4 END AS ma,
          24 AS page_hdr,
          23 + CASE WHEN MAX(coalesce(s.null_frac,0)) > 0 THEN (7 + count(s.attname))/8 ELSE 0::int END
             + CASE WHEN bool_or(att.attname = 'oid' AND att.attnum < 0) THEN 4 ELSE 0 END AS tpl_hdr_size,
          sum((1 - coalesce(s.null_frac, 0)) * coalesce(s.avg_width, 0)) AS tpl_data_size,
          bool_or(att.atttypid = 'pg_catalog.name'::regtype)
            OR sum(CASE WHEN att.attnum > 0 AND s.attname IS NULL THEN 1 ELSE 0 END) > 0 AS is_na
        FROM pg_attribute att
          JOIN pg_class tbl ON att.attrelid = tbl.oid
          JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
          LEFT JOIN pg_stats s ON s.schemaname = ns.nspname AND s.tablename = tbl.relname AND s.inherited = false AND s.attname = att.attname
          LEFT JOIN pg_class toast ON tbl.reltoastrelid = toast.oid
        WHERE NOT att.attisdropped
          AND tbl.relkind IN ('r','m')
          AND ns.nspname NOT IN ('pg_catalog','information_schema')
        GROUP BY 1,2,3,4,5,6,7,8,9,10
      ) inner1
    ) inner2
  ) inner3
) outer_q
WHERE NOT is_na AND bloat_size > 0
ORDER BY bloat_size DESC
LIMIT ` + strconv.Itoa(topBloatN)

	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]tableBloatEntry, 0, topBloatN)
	for rows.Next() {
		var e tableBloatEntry
		if err := rows.Scan(&e.schema, &e.table, &e.size, &e.pct); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanIndexBloat runs the canonical ioguix btree index bloat heuristic.
// Source: https://github.com/ioguix/pgsql-bloat-estimation/blob/master/btree/btree_bloat.sql
// The attpos/att_rel/att_pos logic is subtle and copy-pasted verbatim because
// it's been tuned against real catalogs for years.
func (c *Collector) scanIndexBloat(ctx context.Context) ([]indexBloatEntry, error) {
	q := `SELECT nspname AS schemaname, tblname, idxname,
    CASE WHEN relpages > est_pages_ff THEN (bs*(relpages-est_pages_ff))::bigint ELSE 0::bigint END AS bloat_size,
    CASE WHEN relpages > 0 THEN 100 * (relpages-est_pages_ff)::float / relpages ELSE 0 END AS bloat_pct
FROM (
  SELECT coalesce(1 +
         ceil(reltuples/floor((bs-pageopqdata-pagehdr)/(4+nulldatahdrwidth)::float)), 0
      ) AS est_pages,
      coalesce(1 +
         ceil(reltuples/floor((bs-pageopqdata-pagehdr)*fillfactor/(100*(4+nulldatahdrwidth)::float))), 0
      ) AS est_pages_ff,
      bs, nspname, tblname, idxname, relpages, fillfactor, is_na
  FROM (
      SELECT maxalign, bs, nspname, tblname, idxname, reltuples, relpages, idxoid, fillfactor,
            ( index_tuple_hdr_bm +
                maxalign - CASE
                  WHEN index_tuple_hdr_bm%maxalign = 0 THEN maxalign
                  ELSE index_tuple_hdr_bm%maxalign
                END
              + nulldatawidth + maxalign - CASE
                  WHEN nulldatawidth = 0 THEN 0
                  WHEN nulldatawidth::integer%maxalign = 0 THEN maxalign
                  ELSE nulldatawidth::integer%maxalign
                END
            )::numeric AS nulldatahdrwidth, pagehdr, pageopqdata, is_na
      FROM (
          SELECT n.nspname, i.tblname, i.idxname, i.reltuples, i.relpages,
              i.idxoid, i.fillfactor, current_setting('block_size')::numeric AS bs,
              CASE WHEN version() ~ 'mingw32' OR version() ~ '64-bit|x86_64|ppc64|ia64|amd64' THEN 8 ELSE 4 END AS maxalign,
              24 AS pagehdr,
              16 AS pageopqdata,
              CASE WHEN max(coalesce(s.null_frac,0)) = 0
                  THEN 8
                  ELSE 8 + (( 32 + 8 - 1 ) / 8)
              END AS index_tuple_hdr_bm,
              sum( (1-coalesce(s.null_frac, 0)) * coalesce(s.avg_width, 1024)) AS nulldatawidth,
              max( CASE WHEN i.atttypid = 'pg_catalog.name'::regtype THEN 1 ELSE 0 END ) > 0 AS is_na
          FROM (
              SELECT ct.relname AS tblname, ct.relnamespace, ic.idxname, ic.attpos, ic.indkey, ic.indkey[ic.attpos], ic.reltuples, ic.relpages, ic.tbloid, ic.idxoid, ic.fillfactor,
                  coalesce(a1.attnum, a2.attnum) AS attnum, coalesce(a1.attname, a2.attname) AS attname, coalesce(a1.atttypid, a2.atttypid) AS atttypid,
                  CASE WHEN a1.attnum IS NULL
                  THEN ic.idxname
                  ELSE ct.relname
                  END AS attrelname
              FROM (
                  SELECT idxname, reltuples, relpages, tbloid, idxoid, fillfactor, indkey,
                      pg_catalog.generate_series(1,indnatts) AS attpos
                  FROM (
                      SELECT ci.relname AS idxname, ci.reltuples, ci.relpages, i.indrelid AS tbloid,
                          i.indexrelid AS idxoid,
                          coalesce(substring(
                              array_to_string(ci.reloptions, ' ')
                              from 'fillfactor=([0-9]+)')::smallint, 90) AS fillfactor,
                          i.indnatts,
                          pg_catalog.string_to_array(pg_catalog.textin(
                              pg_catalog.int2vectorout(i.indkey)),' ')::int[] AS indkey
                      FROM pg_catalog.pg_index i
                      JOIN pg_catalog.pg_class ci ON ci.oid = i.indexrelid
                      WHERE ci.relam=(SELECT oid FROM pg_am WHERE amname = 'btree')
                      AND ci.relpages > 0
                  ) AS idx_data
              ) AS ic
              JOIN pg_catalog.pg_class ct ON ct.oid = ic.tbloid
              LEFT JOIN pg_catalog.pg_attribute a1 ON
                  ic.indkey[ic.attpos] <> 0
                  AND a1.attrelid = ic.tbloid
                  AND a1.attnum = ic.indkey[ic.attpos]
              LEFT JOIN pg_catalog.pg_attribute a2 ON
                  ic.indkey[ic.attpos] = 0
                  AND a2.attrelid = ic.idxoid
                  AND a2.attnum = ic.attpos
            ) i
            JOIN pg_catalog.pg_namespace n ON n.oid = i.relnamespace
            JOIN pg_catalog.pg_stats s ON s.schemaname = n.nspname
                                      AND s.tablename = i.attrelname
                                      AND s.attname = i.attname
            GROUP BY 1,2,3,4,5,6,7,8,9,10,11
      ) AS rows_data_stats
  ) AS rows_hdr_pdg_stats
) AS relation_stats
WHERE NOT is_na
  AND relpages > est_pages_ff
  AND nspname NOT IN ('pg_catalog','information_schema')
ORDER BY bloat_size DESC
LIMIT ` + strconv.Itoa(topBloatN)

	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]indexBloatEntry, 0, topBloatN)
	for rows.Next() {
		var e indexBloatEntry
		if err := rows.Scan(&e.schema, &e.table, &e.index, &e.size, &e.pct); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
