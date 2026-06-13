# Oracle Schema Analysis Rules

## Overview

This skill codifies rules from across the Oracle DB Skills library into a single schema analysis reference. Given an existing Oracle physical schema (DDL or live data dictionary), these rules enable:

1. **Reverse-engineering** physical → logical → conceptual models
2. **Issue detection** across 27 rule categories
3. **Logical model improvements** (normalization, SCD, surrogate keys)
4. **Physical model improvements** (indexes, partitioning, compression, tablespace layout, statistics)

Every rule references the source skill file it was derived from and provides a data dictionary query for detection.

---

## 1. Reverse-Engineering: Physical → Logical Model

From a live Oracle schema, the logical model (entities, relationships, cardinality, data types) can be inferred using data dictionary views.

### 1.1 Entity Identification

Each table maps to an entity. Junction tables (composite PK consisting of 2+ foreign keys) represent M:N relationships.

```sql
-- List all entities (tables) in a schema
SELECT table_name, num_rows, last_analyzed,
       CASE WHEN temporary = 'Y' THEN 'Temporary' ELSE 'Permanent' END AS entity_type
FROM   dba_tables
WHERE  owner = :schema_name
ORDER  BY table_name;

-- Identify junction tables (M:N relationships)
-- A junction table has a composite PK where all columns are also FK columns
SELECT t.table_name AS junction_table,
       COUNT(DISTINCT cc.constraint_name) AS fk_count
FROM   dba_constraints t
JOIN   dba_cons_columns tc ON t.constraint_name = tc.constraint_name AND t.owner = tc.owner
JOIN   dba_cons_columns cc ON tc.column_name = cc.column_name AND tc.owner = cc.owner
JOIN   dba_constraints fc ON cc.constraint_name = fc.constraint_name AND cc.owner = fc.owner
WHERE  t.constraint_type = 'P'
AND    fc.constraint_type = 'R'
AND    t.owner = :schema_name
GROUP  BY t.table_name
HAVING COUNT(DISTINCT cc.constraint_name) >= 2
ORDER  BY t.table_name;
```

*Source: [design/erd-design.md](erd-design.md) — Entity types, M:N resolution via junction tables*

### 1.2 Relationship and Cardinality Detection

```sql
-- All relationships (foreign keys) with cardinality inference
SELECT
    c.table_name        AS child_entity,
    cc.column_name      AS fk_column,
    r.table_name        AS parent_entity,
    rc.column_name      AS pk_column,
    CASE
        WHEN EXISTS (
            SELECT 1 FROM dba_constraints u
            WHERE  u.table_name = c.table_name
            AND    u.owner = c.owner
            AND    u.constraint_type IN ('U', 'P')
            AND    EXISTS (
                SELECT 1 FROM dba_cons_columns uc
                WHERE  uc.constraint_name = u.constraint_name
                AND    uc.owner = u.owner
                AND    uc.column_name = cc.column_name
                AND    u.constraint_name != c.constraint_name
            )
        ) THEN '1:1'
        ELSE '1:N'
    END AS cardinality,
    CASE WHEN col.nullable = 'Y' THEN 'Optional' ELSE 'Mandatory' END AS participation
FROM   dba_constraints  c
JOIN   dba_cons_columns cc ON c.constraint_name = cc.constraint_name AND c.owner = cc.owner
JOIN   dba_constraints  r  ON c.r_constraint_name = r.constraint_name AND c.r_owner = r.owner
JOIN   dba_cons_columns rc ON r.constraint_name = rc.constraint_name AND r.owner = rc.owner
JOIN   dba_tab_columns col ON c.owner = col.owner AND c.table_name = col.table_name AND cc.column_name = col.column_name
WHERE  c.constraint_type = 'R'
AND    c.owner = :schema_name
ORDER  BY c.table_name, cc.position;
```

*Source: [design/erd-design.md](erd-design.md) — Cardinality: FK with UNIQUE = 1:1, FK without UNIQUE = 1:N*

### 1.3 Self-Referencing (Recursive) Relationships

```sql
-- Detect hierarchical/recursive relationships
SELECT c.table_name, cc.column_name AS self_fk_column,
       'Recursive (hierarchy)' AS relationship_type
FROM   dba_constraints  c
JOIN   dba_cons_columns cc ON c.constraint_name = cc.constraint_name AND c.owner = cc.owner
JOIN   dba_constraints  r  ON c.r_constraint_name = r.constraint_name AND c.r_owner = r.owner
WHERE  c.constraint_type = 'R'
AND    c.table_name = r.table_name  -- FK references own table
AND    c.owner = :schema_name
ORDER  BY c.table_name;
```

*Source: [design/erd-design.md](erd-design.md) — Self-referencing relationships, CONNECT BY traversal*

### 1.4 Data Type Mapping (Physical → Logical)

| Oracle Physical Type | Logical Type | Notes |
|---|---|---|
| `NUMBER(p)` where p <= 10 | Integer | Standard integer |
| `NUMBER(p,s)` where s > 0 | Decimal | Financial/measurement |
| `NUMBER` (no precision) | Numeric | Unrestricted — flag for review |
| `VARCHAR2(n)` | String | Variable-length text |
| `CHAR(n)` | Fixed String | Fixed-length codes |
| `DATE` | DateTime | Oracle DATE includes time component |
| `TIMESTAMP` | Timestamp | Subsecond precision |
| `TIMESTAMP WITH TIME ZONE` | Timestamp+TZ | Global datetime |
| `CLOB` | Long Text | >4000 characters |
| `BLOB` | Binary | Files, images |
| `RAW(n)` | Short Binary | Hashes, UUIDs |

```sql
-- Map all columns to logical types
SELECT table_name, column_name, data_type,
       data_precision, data_scale, data_length,
       nullable,
       CASE
           WHEN data_type = 'NUMBER' AND data_scale = 0 AND data_precision <= 10 THEN 'Integer'
           WHEN data_type = 'NUMBER' AND data_scale > 0 THEN 'Decimal'
           WHEN data_type = 'NUMBER' AND data_precision IS NULL THEN 'Numeric (review)'
           WHEN data_type = 'VARCHAR2' THEN 'String'
           WHEN data_type = 'CHAR' THEN 'FixedString'
           WHEN data_type = 'DATE' THEN 'DateTime'
           WHEN data_type LIKE 'TIMESTAMP%' AND data_type LIKE '%TIME ZONE%' THEN 'TimestampTZ'
           WHEN data_type LIKE 'TIMESTAMP%' THEN 'Timestamp'
           WHEN data_type = 'CLOB' THEN 'LongText'
           WHEN data_type = 'BLOB' THEN 'Binary'
           WHEN data_type = 'RAW' THEN 'ShortBinary'
           ELSE data_type
       END AS logical_type
FROM   dba_tab_columns
WHERE  owner = :schema_name
ORDER  BY table_name, column_id;
```

*Source: [design/data-modeling.md](data-modeling.md) — Oracle data types and logical mapping*

### 1.5 Derived Attributes (Virtual Columns)

```sql
-- Identify computed/derived attributes
SELECT table_name, column_name, data_default AS expression,
       'Derived (virtual column)' AS attribute_type
FROM   dba_tab_columns
WHERE  virtual_column = 'YES'
AND    owner = :schema_name
ORDER  BY table_name, column_id;
```

*Source: [design/erd-design.md](erd-design.md) — Virtual columns as derived attributes*

---

## 2. Reverse-Engineering: Logical → Conceptual Model

Conceptual models require **business context** that DDL alone does not carry. The quality of the reverse-engineered conceptual model depends on the richness of `COMMENT ON` metadata.

### 2.1 What Can Be Inferred

```sql
-- Extract business context from table/column comments
SELECT t.table_name AS entity,
       t.comments   AS entity_description,
       c.column_name,
       c.comments   AS attribute_description
FROM   dba_tab_comments t
LEFT   JOIN dba_col_comments c
       ON t.owner = c.owner AND t.table_name = c.table_name
WHERE  t.owner = :schema_name
ORDER  BY t.table_name, c.column_name;

-- Extract business rules from CHECK constraints
SELECT table_name, constraint_name, search_condition_vc AS business_rule
FROM   dba_constraints
WHERE  constraint_type = 'C'
AND    owner = :schema_name
AND    constraint_name NOT LIKE 'SYS%'  -- exclude NOT NULL system constraints
ORDER  BY table_name;
```

### 2.2 What Cannot Be Inferred

- **Business process context**: Why entities exist, what workflows they support
- **Domain language**: Proper business names vs. abbreviated column names
- **Non-DDL business rules**: Rules enforced only in application code or triggers
- **Entity groupings**: Which entities form bounded contexts or subject areas

> These gaps must be filled by interviewing domain experts or reading application documentation.

*Source: [design/erd-design.md](erd-design.md), [design/data-modeling.md](data-modeling.md)*

---

## 3. Issue Detection Rules

### 3.1 Critical Issues

#### Rule 1: Tables Without Primary Keys

Every table must have a primary key for entity integrity.

```sql
SELECT t.table_name, t.num_rows
FROM   dba_tables t
WHERE  t.owner = :schema_name
AND    NOT EXISTS (
    SELECT 1 FROM dba_constraints c
    WHERE  c.owner = t.owner
    AND    c.table_name = t.table_name
    AND    c.constraint_type = 'P'
)
AND    t.temporary = 'N'
ORDER  BY t.num_rows DESC NULLS LAST;
```

**Fix:** Add a primary key — either a surrogate identity column (12c+) or a natural key.

*Source: [design/erd-design.md](erd-design.md) — "Always define primary keys on every table"*

#### Rule 2: Foreign Keys Without Indexes

Oracle does not automatically create indexes on FK columns. Without them, parent-row deletes cause full table locks on the child table, and join performance degrades.

```sql
SELECT c.table_name, cc.column_name AS fk_column, c.constraint_name
FROM   dba_constraints  c
JOIN   dba_cons_columns cc
       ON c.constraint_name = cc.constraint_name AND c.owner = cc.owner
WHERE  c.constraint_type = 'R'
AND    c.owner = :schema_name
AND    NOT EXISTS (
    SELECT 1 FROM dba_ind_columns ic
    WHERE  ic.table_owner = c.owner
    AND    ic.table_name  = c.table_name
    AND    ic.column_name = cc.column_name
    AND    ic.column_position = cc.position
)
ORDER  BY c.table_name, cc.position;
```

**Fix:** `CREATE INDEX IX_<table>_<column> ON <table> (<fk_column>);`

*Source: [design/erd-design.md](erd-design.md), [performance/index-strategy.md](../performance/index-strategy.md) — "Oracle does not automatically create indexes on foreign key columns"*

#### Rule 3: Bitmap Indexes on OLTP Tables

Bitmap indexes lock at the bitmap segment level during DML — a single insert can block dozens of concurrent transactions.

```sql
SELECT i.table_name, i.index_name, i.index_type,
       t.num_rows,
       NVL(m.inserts, 0) + NVL(m.updates, 0) + NVL(m.deletes, 0) AS dml_count
FROM   dba_indexes i
JOIN   dba_tables  t ON i.owner = t.owner AND i.table_name = t.table_name
LEFT   JOIN dba_tab_modifications m ON i.owner = m.table_owner AND i.table_name = m.table_name
WHERE  i.index_type = 'BITMAP'
AND    i.owner = :schema_name
AND    (NVL(m.inserts, 0) + NVL(m.updates, 0) + NVL(m.deletes, 0)) > 1000
ORDER  BY dml_count DESC;
```

**Fix:** Replace with B-tree indexes on OLTP tables. Reserve bitmap indexes for read-heavy data warehouse fact tables.

*Source: [performance/index-strategy.md](../performance/index-strategy.md), [design/data-modeling.md](data-modeling.md) — "Never use bitmap indexes on OLTP tables"*

### 3.2 High-Severity Issues

#### Rule 4: Reserved Words as Identifiers

```sql
SELECT table_name, column_name
FROM   dba_tab_columns
WHERE  owner = :schema_name
AND    column_name IN (
    'ACCESS','ADD','ALL','ALTER','AND','ANY','AS','ASC','AUDIT','BETWEEN',
    'BY','CHAR','CHECK','CLUSTER','COLUMN','COMMENT','COMPRESS','CONNECT',
    'CREATE','CURRENT','DATE','DECIMAL','DEFAULT','DELETE','DESC','DISTINCT',
    'DROP','ELSE','EXCLUSIVE','EXISTS','FILE','FLOAT','FOR','FROM','GRANT',
    'GROUP','HAVING','IDENTIFIED','IMMEDIATE','IN','INCREMENT','INDEX',
    'INITIAL','INSERT','INTEGER','INTERSECT','INTO','IS','LEVEL','LIKE',
    'LOCK','LONG','MAXEXTENTS','MINUS','MODE','MODIFY','NOAUDIT',
    'NOCOMPRESS','NOT','NOWAIT','NULL','NUMBER','OF','OFFLINE','ON','ONLINE',
    'OPTION','OR','ORDER','PCTFREE','PRIOR','PUBLIC','RAW','RENAME',
    'RESOURCE','REVOKE','ROW','ROWID','ROWNUM','ROWS','SELECT','SESSION',
    'SET','SHARE','SIZE','SMALLINT','START','SUCCESSFUL','SYNONYM','SYSDATE',
    'TABLE','THEN','TO','TRIGGER','UID','UNION','UNIQUE','UPDATE','USER',
    'VALIDATE','VALUES','VARCHAR','VARCHAR2','VIEW','WHENEVER','WHERE','WITH'
)
ORDER  BY table_name, column_name;
```

**Fix:** Rename columns to descriptive alternatives (e.g., `DATE` → `ORDER_DATE`, `COMMENT` → `ORDER_COMMENT`).

*Source: [design/erd-design.md](erd-design.md) — Oracle reserved words list*

#### Rule 5: System-Generated Constraint Names

Anonymous constraints receive names like `SYS_C001234`, making maintenance and error diagnosis extremely difficult.

```sql
SELECT table_name, constraint_name, constraint_type, search_condition_vc
FROM   dba_constraints
WHERE  owner = :schema_name
AND    generated = 'GENERATED NAME'
AND    constraint_type != 'C'  -- exclude simple NOT NULL
ORDER  BY table_name, constraint_type;
```

**Fix:** Rename constraints: `ALTER TABLE <t> RENAME CONSTRAINT SYS_C001234 TO PK_<table>;`

*Source: [design/erd-design.md](erd-design.md) — "Name all constraints explicitly"*

#### Rule 6: Stale or Missing Optimizer Statistics

```sql
-- Tables never analyzed
SELECT table_name, num_rows, blocks
FROM   dba_tables
WHERE  owner = :schema_name
AND    last_analyzed IS NULL
AND    temporary = 'N'
ORDER  BY table_name;

-- Tables with stale statistics
SELECT table_name, stale_stats, last_analyzed
FROM   dba_tab_statistics
WHERE  owner = :schema_name
AND    stale_stats = 'YES'
ORDER  BY table_name;
```

**Fix:** `EXEC DBMS_STATS.GATHER_TABLE_STATS(:schema_name, :table_name, estimate_percent => DBMS_STATS.AUTO_SAMPLE_SIZE);`

*Source: [performance/optimizer-stats.md](../performance/optimizer-stats.md) — "Statistics must be gathered after bulk loads"*

#### Rule 7: Unpartitioned Large Tables

Tables exceeding 50 million rows without partitioning suffer full table scans and slow maintenance.

```sql
SELECT table_name, num_rows, blocks,
       ROUND(blocks * 8192 / 1024 / 1024 / 1024, 2) AS size_gb
FROM   dba_tables
WHERE  owner = :schema_name
AND    num_rows > 50000000
AND    partitioned = 'NO'
ORDER  BY num_rows DESC;
```

**Fix:** Add range partitioning on the most commonly filtered date/time column. Use `ALTER TABLE ... MODIFY PARTITION BY RANGE ... ONLINE` (12.2+).

*Source: [design/partitioning-strategy.md](partitioning-strategy.md) — "Partitioning tables with fewer than a few million rows adds overhead... Only partition tables where partition pruning will eliminate a meaningful portion of I/O"*

#### Rule 8: Dates Stored as VARCHAR2

Storing dates as strings prevents index range scans, allows invalid dates, and breaks NLS-dependent comparisons.

```sql
SELECT table_name, column_name, data_type, data_length
FROM   dba_tab_columns
WHERE  owner = :schema_name
AND    data_type = 'VARCHAR2'
AND    (   UPPER(column_name) LIKE '%DATE%'
        OR UPPER(column_name) LIKE '%TIME%'
        OR UPPER(column_name) LIKE '%CREATED%'
        OR UPPER(column_name) LIKE '%MODIFIED%'
        OR UPPER(column_name) LIKE '%UPDATED%'
       )
ORDER  BY table_name, column_name;
```

**Fix:** Convert to `DATE` or `TIMESTAMP` type. Use `ALTER TABLE ... MODIFY (col DATE)` after cleansing data.

*Source: [design/data-modeling.md](data-modeling.md) — "Use DATE for date-only data... Avoid storing dates as VARCHAR2"*

#### Rule 9: User Objects in SYSTEM or USERS Tablespace

```sql
SELECT table_name, tablespace_name, num_rows
FROM   dba_tables
WHERE  owner = :schema_name
AND    tablespace_name IN ('SYSTEM', 'SYSAUX', 'USERS')
AND    owner NOT IN ('SYS', 'SYSTEM', 'DBSNMP', 'OUTLN')
ORDER  BY tablespace_name, table_name;
```

**Fix:** Move to a dedicated application tablespace: `ALTER TABLE ... MOVE TABLESPACE app_data ONLINE;`

*Source: [design/tablespace-design.md](tablespace-design.md) — "Never store application objects in SYSTEM or SYSAUX"*

#### Rule 10: Unlimited AUTOEXTEND Without MAXSIZE

A runaway query or insert loop can exhaust the filesystem and crash the database.

```sql
SELECT file_name, tablespace_name,
       ROUND(bytes / 1073741824, 2) AS current_gb,
       autoextensible,
       ROUND(maxbytes / 1073741824, 2) AS max_gb
FROM   dba_data_files
WHERE  autoextensible = 'YES'
AND    maxbytes = 34359721984  -- ~32GB = Oracle "unlimited" sentinel for 8K blocks
ORDER  BY tablespace_name;
```

**Fix:** Set explicit MAXSIZE: `ALTER DATABASE DATAFILE '<file>' AUTOEXTEND ON NEXT 1G MAXSIZE 200G;`

*Source: [design/tablespace-design.md](tablespace-design.md) — "Cap AUTOEXTEND with a realistic MAXSIZE"*

#### Rule 11: CSV Values Stored in Single Columns

Multi-valued columns violate 1NF, prevent indexing, and make joins impossible.

```sql
-- Heuristic: find columns likely storing CSV (large VARCHAR2 with commas in data)
-- This requires sampling actual data
SELECT table_name, column_name, data_type, data_length
FROM   dba_tab_columns
WHERE  owner = :schema_name
AND    data_type = 'VARCHAR2'
AND    data_length >= 200
AND    UPPER(column_name) LIKE '%LIST%'
   OR  UPPER(column_name) LIKE '%TAGS%'
   OR  UPPER(column_name) LIKE '%MEMBERS%'
   OR  UPPER(column_name) LIKE '%IDS%'
ORDER  BY table_name, column_name;
```

**Fix:** Extract into a child table with a composite primary key.

*Source: [design/erd-design.md](erd-design.md) — "Storing Multiple Values in a Single Column" common mistake*

### 3.3 Medium-Severity Issues

#### Rule 12: PCTFREE Misaligned to Workload

```sql
SELECT t.table_name, t.pct_free, t.num_rows,
       NVL(m.updates, 0) AS update_count,
       CASE
           WHEN NVL(m.updates, 0) = 0 AND t.pct_free > 5
               THEN 'Wasteful: append-only table with high PCTFREE'
           WHEN NVL(m.updates, 0) > t.num_rows * 0.1 AND t.pct_free < 15
               THEN 'Risk: heavily updated table with low PCTFREE (row chaining)'
           ELSE 'OK'
       END AS assessment
FROM   dba_tables t
LEFT   JOIN dba_tab_modifications m ON t.owner = m.table_owner AND t.table_name = m.table_name
WHERE  t.owner = :schema_name
AND    t.num_rows > 10000
ORDER  BY t.table_name;
```

*Source: [design/data-modeling.md](data-modeling.md) — PCTFREE tuning guide by workload*

#### Rule 13: Data and Indexes in Same Tablespace

```sql
SELECT t.table_name, t.tablespace_name AS data_ts,
       i.index_name, i.tablespace_name AS index_ts
FROM   dba_tables  t
JOIN   dba_indexes i ON t.owner = i.table_owner AND t.table_name = i.table_name
WHERE  t.owner = :schema_name
AND    t.tablespace_name = i.tablespace_name
AND    t.tablespace_name NOT IN ('SYSTEM', 'SYSAUX')
ORDER  BY t.table_name, i.index_name;
```

**Fix:** Move indexes to a separate tablespace: `ALTER INDEX ... REBUILD TABLESPACE app_idx;`

*Source: [design/tablespace-design.md](tablespace-design.md) — "Separate data from indexes"*

#### Rule 14: Non-Power-of-2 Hash Partition Count

```sql
SELECT table_name, partitioning_type, subpartitioning_type,
       partition_count
FROM   dba_part_tables
WHERE  owner = :schema_name
AND    (partitioning_type = 'HASH' OR subpartitioning_type = 'HASH')
AND    partition_count NOT IN (2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
ORDER  BY table_name;
```

**Fix:** Recreate with a power-of-2 partition count for guaranteed even distribution.

*Source: [design/partitioning-strategy.md](partitioning-strategy.md) — "Hash partitions must be a power of 2"*

#### Rule 15: MSSM Tablespaces (Legacy)

```sql
SELECT tablespace_name, segment_space_management, extent_management
FROM   dba_tablespaces
WHERE  segment_space_management = 'MANUAL'
AND    contents = 'PERMANENT'
ORDER  BY tablespace_name;
```

**Fix:** Create new ASSM tablespace and move objects: `SEGMENT SPACE MANAGEMENT AUTO`.

*Source: [design/tablespace-design.md](tablespace-design.md) — "Always use ASSM"*

#### Rule 16: Dictionary-Managed Tablespaces

```sql
SELECT tablespace_name, extent_management
FROM   dba_tablespaces
WHERE  extent_management = 'DICTIONARY'
ORDER  BY tablespace_name;
```

**Fix:** `EXEC DBMS_SPACE_ADMIN.TABLESPACE_MIGRATE_TO_LOCAL(:tablespace_name);`

*Source: [design/tablespace-design.md](tablespace-design.md) — "All new tablespaces should be locally managed"*

#### Rule 17: Missing NOT NULL on Mandatory Attributes

```sql
-- Find nullable FK columns (likely mandatory relationships)
SELECT c.table_name, cc.column_name, 'Nullable FK — likely should be NOT NULL' AS issue
FROM   dba_constraints  c
JOIN   dba_cons_columns cc ON c.constraint_name = cc.constraint_name AND c.owner = cc.owner
JOIN   dba_tab_columns  tc ON c.owner = tc.owner AND c.table_name = tc.table_name AND cc.column_name = tc.column_name
WHERE  c.constraint_type = 'R'
AND    c.owner = :schema_name
AND    tc.nullable = 'Y'
ORDER  BY c.table_name, cc.column_name;
```

*Source: [design/erd-design.md](erd-design.md) — "Enforce NOT NULL at the database level"*

#### Rule 18: Unused Indexes

```sql
-- Oracle 12c+ index usage tracking
SELECT i.table_name, i.index_name, i.index_type,
       u.total_access_count, u.last_used
FROM   dba_indexes i
LEFT   JOIN dba_index_usage u ON i.owner = u.owner AND i.index_name = u.name
WHERE  i.owner = :schema_name
AND    (u.total_access_count = 0 OR u.total_access_count IS NULL)
AND    i.index_type != 'LOB'
ORDER  BY i.table_name, i.index_name;
```

**Fix:** Drop unused indexes to eliminate DML overhead. Test with `ALTER INDEX ... INVISIBLE` first.

*Source: [performance/index-strategy.md](../performance/index-strategy.md) — "Monitor unused indexes, drop unused indexes"*

#### Rule 19: Natural Keys Used as Dimension Primary Keys

```sql
-- Heuristic: dimension tables (DIM_ prefix) using non-identity columns as PK
SELECT t.table_name, tc.column_name AS pk_column, tc.data_type,
       tc.identity_column
FROM   dba_tables t
JOIN   dba_constraints c ON t.owner = c.owner AND t.table_name = c.table_name AND c.constraint_type = 'P'
JOIN   dba_cons_columns cc ON c.constraint_name = cc.constraint_name AND c.owner = cc.owner
JOIN   dba_tab_columns tc ON t.owner = tc.owner AND t.table_name = tc.table_name AND cc.column_name = tc.column_name
WHERE  t.owner = :schema_name
AND    UPPER(t.table_name) LIKE 'DIM_%'
AND    tc.identity_column = 'NO'
AND    tc.data_type IN ('VARCHAR2', 'CHAR')  -- natural/business key used as PK
ORDER  BY t.table_name;
```

**Fix:** Add a surrogate key (`NUMBER GENERATED ALWAYS AS IDENTITY`) and demote the natural key to a unique constraint.

*Source: [design/data-modeling.md](data-modeling.md) — "Use surrogate keys in dimension tables, never business/natural keys"*

### 3.4 Low-Severity Issues

#### Rule 20: Missing Column Comments on Derived Fields

```sql
SELECT t.table_name, t.column_name, t.data_default AS expression
FROM   dba_tab_columns t
LEFT   JOIN dba_col_comments c ON t.owner = c.owner AND t.table_name = c.table_name AND t.column_name = c.column_name
WHERE  t.owner = :schema_name
AND    t.virtual_column = 'YES'
AND    (c.comments IS NULL OR c.comments = '')
ORDER  BY t.table_name, t.column_name;
```

**Fix:** `COMMENT ON COLUMN <table>.<column> IS 'Derived: <formula description>';`

*Source: [design/data-modeling.md](data-modeling.md) — "Document the grain of every fact table explicitly"*

---

## 4. Logical Model Improvements

### 4.1 Normalization Violation Detection

#### Repeating Groups (1NF Violation)

Columns with numbered suffixes (e.g., `PHONE1`, `PHONE2`, `PHONE3`) indicate repeating groups that should be extracted into a child table.

```sql
-- Heuristic: detect columns with numeric suffix patterns
SELECT table_name,
       REGEXP_REPLACE(column_name, '[0-9]+$', '') AS base_name,
       COUNT(*) AS count_in_group,
       LISTAGG(column_name, ', ') WITHIN GROUP (ORDER BY column_name) AS columns
FROM   dba_tab_columns
WHERE  owner = :schema_name
AND    REGEXP_LIKE(column_name, '.*[0-9]+$')
GROUP  BY table_name, REGEXP_REPLACE(column_name, '[0-9]+$', '')
HAVING COUNT(*) >= 2
ORDER  BY table_name;
```

**Fix:** Create a child table with composite PK `(parent_id, type_or_sequence)`.

*Source: [design/erd-design.md](erd-design.md) — 1NF: "No repeating groups or arrays"*

#### Transitive Dependencies (3NF Violation)

Columns that appear to carry redundant descriptive data from a related entity (e.g., `DEPT_ID` + `DEPT_NAME` in an EMPLOYEE table).

```sql
-- Heuristic: find potential transitive dependencies
-- Columns ending in _NAME or _DESC alongside a corresponding _ID column
SELECT t1.table_name,
       t1.column_name AS id_column,
       t2.column_name AS name_column,
       'Potential 3NF violation: descriptive column alongside FK' AS issue
FROM   dba_tab_columns t1
JOIN   dba_tab_columns t2 ON t1.owner = t2.owner AND t1.table_name = t2.table_name
WHERE  t1.owner = :schema_name
AND    t1.column_name LIKE '%\_ID' ESCAPE '\'
AND    t2.column_name = REPLACE(t1.column_name, '_ID', '_NAME')
AND    NOT EXISTS (
    SELECT 1 FROM dba_constraints c
    WHERE  c.owner = t1.owner AND c.table_name = t1.table_name
    AND    c.constraint_type = 'P'
    AND    EXISTS (
        SELECT 1 FROM dba_cons_columns cc
        WHERE  cc.constraint_name = c.constraint_name
        AND    cc.owner = c.owner
        AND    cc.column_name = t1.column_name
    )
)
ORDER  BY t1.table_name;
```

**Fix:** Move the descriptive column to the referenced table and join when needed.

*Source: [design/erd-design.md](erd-design.md) — 3NF: "No transitive dependencies"*

### 4.2 Missing SCD Strategy on Dimension Tables

```sql
-- Dimension tables without SCD tracking columns
SELECT table_name
FROM   dba_tables
WHERE  owner = :schema_name
AND    UPPER(table_name) LIKE 'DIM_%'
AND    NOT EXISTS (
    SELECT 1 FROM dba_tab_columns c
    WHERE  c.owner = dba_tables.owner
    AND    c.table_name = dba_tables.table_name
    AND    UPPER(c.column_name) IN ('EFFECTIVE_FROM', 'EFFECTIVE_TO', 'IS_CURRENT',
                                      'VALID_FROM', 'VALID_TO', 'CURRENT_FLAG')
)
ORDER  BY table_name;
```

**Fix:** Add SCD Type 2 columns (`effective_from DATE`, `effective_to DATE`, `is_current CHAR(1)`).

*Source: [design/data-modeling.md](data-modeling.md) — "Failing to decide on SCD type before go-live means historical changes are silently lost"*

---

## 5. Physical Model Improvements

### 5.1 Partitioning Candidates

```sql
-- Large tables with date columns that are partition candidates
SELECT t.table_name, t.num_rows,
       ROUND(t.blocks * 8192 / 1024 / 1024 / 1024, 2) AS size_gb,
       c.column_name AS date_column
FROM   dba_tables t
JOIN   dba_tab_columns c ON t.owner = c.owner AND t.table_name = c.table_name
WHERE  t.owner = :schema_name
AND    t.num_rows > 50000000
AND    t.partitioned = 'NO'
AND    c.data_type IN ('DATE', 'TIMESTAMP', 'TIMESTAMP(6)')
AND    (UPPER(c.column_name) LIKE '%DATE%' OR UPPER(c.column_name) LIKE '%TIME%')
ORDER  BY t.num_rows DESC;
```

*Source: [design/partitioning-strategy.md](partitioning-strategy.md)*

### 5.2 Compression Candidates

```sql
-- Large tables without compression
SELECT table_name, num_rows,
       ROUND(blocks * 8192 / 1024 / 1024 / 1024, 2) AS size_gb,
       compression, compress_for
FROM   dba_tables
WHERE  owner = :schema_name
AND    compression = 'DISABLED'
AND    num_rows > 10000000
ORDER  BY blocks DESC;
```

**Fix:** For DW on Exadata: `COMPRESS FOR QUERY HIGH`. For DW on standard storage: `ROW STORE COMPRESS ADVANCED`. For append-only: `COMPRESS BASIC`.

*Source: [design/data-modeling.md](data-modeling.md), [architecture/exadata-features.md](../architecture/exadata-features.md)*

### 5.3 Stale Statistics Remediation

```sql
-- Gather stats for all stale tables in a schema
EXEC DBMS_STATS.GATHER_SCHEMA_STATS(
    ownname          => :schema_name,
    options          => 'GATHER STALE',
    estimate_percent => DBMS_STATS.AUTO_SAMPLE_SIZE,
    degree           => DBMS_STATS.AUTO_DEGREE
);
```

*Source: [performance/optimizer-stats.md](../performance/optimizer-stats.md)*

### 5.4 Row-Level Triggers on Large Fact Tables

```sql
SELECT t.table_name, tr.trigger_name, tr.trigger_type,
       tab.num_rows
FROM   dba_triggers tr
JOIN   dba_tables tab ON tr.owner = tab.owner AND tr.table_name = tab.table_name
CROSS  JOIN LATERAL (SELECT tr.table_name FROM DUAL) t
WHERE  tr.owner = :schema_name
AND    tr.trigger_type LIKE '%EACH ROW%'
AND    tab.num_rows > 10000000
ORDER  BY tab.num_rows DESC;
```

**Fix:** Move trigger logic to ETL process or package-level bulk operations.

*Source: [design/data-modeling.md](data-modeling.md) — "Avoid triggers on DW fact tables"*

---

## 6. Complete Analysis Workflow

Run these steps in order for a full schema health check:

1. **Catalog entities** — Section 1.1 (entity identification)
2. **Map relationships** — Sections 1.2, 1.3 (cardinality, hierarchies)
3. **Extract business context** — Section 2.1 (comments, check constraints)
4. **Run critical checks** — Section 3.1 (PKs, FK indexes, bitmap on OLTP)
5. **Run high-severity checks** — Section 3.2 (reserved words, stats, partitioning, dates)
6. **Run medium-severity checks** — Section 3.3 (PCTFREE, tablespaces, hash partitions)
7. **Assess normalization** — Section 4.1 (repeating groups, transitive dependencies)
8. **Check dimensional model** — Section 4.2 (SCD strategy)
9. **Physical optimization** — Section 5 (partitioning, compression, statistics, triggers)
10. **Document findings** — Prioritize by severity, estimate remediation effort

---

## Oracle Version Notes (19c vs 26ai)

- Baseline guidance in this file is valid for Oracle Database 19c unless a newer minimum version is explicitly called out.
- Features marked as 21c, 23c, or 23ai should be treated as Oracle Database 26ai-capable features; keep 19c-compatible alternatives for mixed-version estates.
- For dual-support environments, test syntax and package behavior in both 19c and 26ai because defaults and deprecations can differ by release update.

| Feature Used in This Skill | Minimum Version |
|---|---|
| `DBA_INDEX_USAGE` view | 12c R2 (12.2) |
| `ALTER TABLE ... MODIFY PARTITION BY ... ONLINE` | 12c R2 (12.2) |
| Identity columns (`GENERATED ALWAYS AS IDENTITY`) | 12c (12.1) |
| Virtual columns | 11g R1 |
| `SEARCH_CONDITION_VC` in `DBA_CONSTRAINTS` | 12c (12.1) |
| Automatic List Partitioning | 12c R2 (12.2) |
| Interval Partitioning | 11g R1 |

---

## Sources

This skill consolidates rules from the following skill files in this repository:

- [skills/design/erd-design.md](erd-design.md) — Entity design, normalization, naming conventions, constraint rules
- [skills/design/data-modeling.md](data-modeling.md) — Logical/physical modeling, star/snowflake schemas, SCD, compression, PCTFREE
- [skills/design/partitioning-strategy.md](partitioning-strategy.md) — Partitioning types, pruning, local vs global indexes
- [skills/design/tablespace-design.md](tablespace-design.md) — Tablespace layout, ASSM vs MSSM, sizing, autoextend
- [skills/performance/index-strategy.md](../performance/index-strategy.md) — B-tree vs bitmap, FK indexes, unused index detection
- [skills/performance/optimizer-stats.md](../performance/optimizer-stats.md) — Statistics gathering, staleness, histograms
- [skills/architecture/exadata-features.md](../architecture/exadata-features.md) — HCC compression requirements
- [skills/plsql/plsql-package-design.md](../plsql/plsql-package-design.md) — Package design anti-patterns
- [skills/sql-dev/sql-best-practices.md](../sql-dev/sql-best-practices.md) — Implicit type conversions, bind variables

Official Oracle documentation:
- [Oracle Database 23ai Database Reference — Static Data Dictionary Views](https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/static-data-dictionary-views.html)
- [Oracle Database 23ai SQL Language Reference — CREATE TABLE](https://docs.oracle.com/en/database/oracle/oracle-database/23/sqlrf/CREATE-TABLE.html)
- [Oracle Database 23ai Administrator's Guide — Managing Schema Objects](https://docs.oracle.com/en/database/oracle/oracle-database/23/admin/managing-schema-objects.html)
