# smb.conf Parsing Specification

Status: derived from Samba source (verified), not from the man page.
Purpose: define the exact behavior a parser must reproduce for the
`cmd/auth/templates/smb.conf.tmpl` output and this project's needs.

## Sources of truth

All behavior below was checked against these files:

| Concern | File | Function |
|---|---|---|
| Line splitting / continuation | `lib/util/params.c` | `pm_process()` |
| Lexical parsing (lines, continuation, trimming) | `lib/util/tini.c` | `tini_parse()`, `get_line()`, `parse_param()`, `trim_one_space()` |
| Parameter semantics / storage | `lib/param/loadparm.c` | `set_variable_helper()`, `lpcfg_string_set()` |
| String retrieval | `lib/param/loadparm.c` | `lpcfg_string()` (currently identity) |
| List parsing | `lib/util/util_strlist_v3.c` | `str_list_make_v3()` |
| Token quoting | `lib/util/util_str.c` | `next_token_talloc()` / `next_token_internal_talloc()` |
| Display / dump | `lib/param/loadparm.c` | `lpcfg_print_parameter()`, `lpcfg_dump_a_service()` |
| Parameter type definitions | `docs-xml/smbdotconf/**/*.xml` | `<samba:parameter type="...">` |
| `comment` quote trimming (printcap path only) | `source3/param/loadparm.c` | `trim_char(comment, '"', '"')` |

Repository snapshot used for line references: `lib/util/params.c` at commit
`f6fddd2232c9f94b591d52b5689d3ee03cc19be6`.

## Non-goals

- This does not describe Samba 3 `params.c` legacy behavior.
- This does not describe variable substitution (`%U`, `%N`, ...). In the
  inspected version `standard_sub_basic()` is disabled inside `lpcfg_string()`.

---

## 1. File / line model

### 1.1 Lines

- A logical line is read by `get_line()`.
- Lines whose first non-space character is `#` or `;` are **comments** and
  are skipped entirely.
- Blank lines are skipped.
- Leading whitespace is ignored.

### 1.2 Whitespace normalization

- Runs of whitespace **inside** a logical line are collapsed to a single
  space (`get_line()`: "Zap multiple spaces to one"). This applies to
  whitespace between characters, including inside values.
- Exactly **one** leading and **one** trailing space is trimmed from a value
  by `trim_one_space()`. Values are not fully trimmed.

### 1.3 Line continuation

A line **continues** onto the next line when:

1. Its last character is `\` (backslash), or
2. Its last two characters are `\` followed by a space (`\ `).

In both cases the backslash is removed and the following line is appended.
This is the **only** special meaning a backslash has in the current parser.
There is **no** backslash-escape processing: `\\`, `\s`, `\t`, `\"`, etc.
are all kept literally by `tini.c` and `loadparm.c`.

Consequences:

- `winbind separator = \` alone on a line is **not representable**; the
  trailing `\` is consumed as a continuation. A `\` that is followed by any
  other content on the same logical line is fine.
- A trailing backslash cannot be escaped to keep it.

### 1.4 Section headers

- A line starting with `[` is a section header: `[name]`, terminated by `]`.
- Section name is the text between the brackets, after whitespace
  normalization.
- `[global]` is the global section.

### 1.5 Parameter lines

- Format: `name = value`.
- The **first** `=` is the separator; later `=` are part of the value.
- `name` is the text before `=`, with one leading/trailing space trimmed.
- `value` is the text after `=`, with one leading/trailing space trimmed.
- A line without `=` is ignored (unless `allow_empty_values` is set, which is
  not used for `smb.conf`).
- Parameter names are case-insensitive for lookup.

---

## 2. Value typing

The type of the parameter decides how the value is interpreted. A parser
that only reproduces `tini.c` will have no quote removal; quote removal only
happens for list-typed parameters.

Types used by the template:

| Parameter | Type (XML) | Storage / parse behavior |
|---|---|---|
| `security` | enum | Token compared against enum list. |
| `realm` | string | Verbatim; quotes are literal characters. |
| `workgroup` | ustring | Verbatim, stored uppercased. |
| `netbios name` | ustring | Verbatim, stored uppercased. |
| `winbind use default domain` | boolean | `yes`/`no` (also true/false/on/off/1/0). |
| `winbind separator` | string | Verbatim; must be a single character. |
| `idmap config * : backend` | parametric | Key/value; value verbatim. |
| `idmap config * : range` | parametric | Value verbatim. |
| `kerberos method` | enum | Token compared against enum list. |
| `dedicated keytab file` | string | Verbatim. |
| `sync machine password to keytab` | cmdlist | List parse (see §3). |
| `winbind refresh tickets` | boolean | `yes`/`no`. |
| `admin users` | cmdlist | List parse (see §3). |
| `comment` | string | Verbatim (no quote stripping in the generic path). |

Notes:

- `ustring` = same as string but uppercased when stored.
- Parametric options are addressed as `type : option` and stored separately
  (`get_parametric_helper()` / `set_param_opt()`).
- `comment` has an additional quote trim in the **printcap** code path
  (`trim_char(comment, '"', '"')`), not in the generic config path.

---

## 3. List parsing (`P_LIST` / `P_CMDLIST` / cmdlist)

Entry: `str_list_make_v3(value, NULL)`.

### 3.1 Separators

Default separator set when none is supplied:

```
" \t,;\n\r"
```

That is: space, tab, comma, semicolon, newline, carriage return.

### 3.2 Tokenization algorithm

Repeatedly call `next_token_talloc()`, which does:

1. Skip any leading separator characters.
2. Scan forward. A separator outside double quotes ends the token.
3. Every `"` toggles a `quoted` boolean.
4. While copying the token, **omit every `"`**; copy all other characters.
5. Advance past the terminating separator and repeat.

### 3.3 Rules and consequences

- Surrounding double quotes are **removed** for list values.
- Quoted regions may contain the separators (space, comma, `;`) without
  splitting.
- Unquoted `,` and `;` **do** split tokens.
- **No backslash escaping.** `\` is copied literally. `\"` does not escape
  the quote; the `\` is kept and the `"` still toggles quoting.
- Single quotes are literal characters and have no grouping effect.
- Adjacent / repeated separators produce no empty tokens.
- Empty or NULL input yields an empty/NULL list.
- Unbalanced quotes: the rest of the string remains in the quoted state and
  becomes one token.

Example:

```
admin users = "DOMAIN\\administrator"
```

produces one token `DOMAIN\\administrator` (two backslashes preserved,
quotes gone).

---

## 4. String-typed values

For `string` / `ustring`:

- Value is stored as parsed by `tini.c` (whitespace-collapsed, one edge space
  trimmed, continuations joined).
- No quote removal: `"` characters are part of the stored value.
- No backslash unescaping.
- `ustring` is uppercased on store.

Implication for the template: do **not** wrap string-typed values in quotes
expecting them to be stripped. Quote only list-typed values.

---

## 5. Display (`testparm` / `lp_dump`)

`lpcfg_print_parameter()`:

- `P_STRING` / `P_USTRING`: printed with `%s`, verbatim (so literal quotes, if
  present in the stored value, would be shown).
- `P_LIST`: joined with `", "`; a token containing a space is wrapped in
  double quotes on output.
- `P_CMDLIST`: joined with a single space; tokens containing a space are
  quoted on output.

`lpcfg_dump_a_service()` prints `name = value` using the above.

So `testparm` output is a canonical rendering, not a byte-for-byte echo of
the input. Quote differences you see in `testparm` for list parameters come
from list tokenization, not from a generic quote-stripping pass.

---

## 6. Template-specific rules and known issues

Template: `cmd/auth/templates/smb.conf.tmpl` (mirrored at
`docs/specs/smb.conf.tmpl`).

| Field | Type | Rule for the template |
|---|---|---|
| `security = ads` | enum | Plain token. |
| `realm = {{ .Realm }}` | string | No quotes unless the value genuinely contains quotes; quote characters become literal. |
| `workgroup = {{ .Workgroup }}` | ustring | Plain token; uppercased on store. |
| `netbios name = {{ .Hostname }}` | ustring | Plain token. |
| `winbind use default domain = no` | boolean | `yes`/`no`. |
| `winbind separator = {{ .Separator }}` | string | Must be exactly one character. MUST NOT be a bare trailing `\`; that is line continuation. |
| `idmap config * : backend = tdb` | parametric | Plain token. |
| `idmap config * : range = 3000-7999` | parametric | Plain token. |
| `idmap config <WG> : backend = rid` | parametric | Plain token. |
| `idmap config <WG> : range = 10000-999999` | parametric | Plain token. |
| `kerberos method = secrets and keytab` | enum | One enum value; spaces are part of the enum token and are preserved as single spaces. |
| `dedicated keytab file = {{ .KeytabPath }}` | string | Verbatim; spaces preserved; quotes are literal. |
| `sync machine password to keytab = "..."` | cmdlist | Quotes are stripped by list tokenization; safe. |
| `winbind refresh tickets = yes` | boolean | `yes`/`no`. |

### 6.1 Known bug: trailing `winbind separator`

If `.Separator` renders as `\`, the template emits:

```
winbind separator = \
```

The trailing `\` is a continuation, so the next line is swallowed. Fixes:

- choose a non-`\` separator, or
- ensure a non-space character follows the `\` on the same line, or
- special-case rendering so the separator is never the last character.

### 6.2 `sync machine password to keytab`

The value is `cmdlist`, so the surrounding quotes are removed correctly by
`str_list_make_v3()`. The value is split on space, `,`, `;`, tab and
newlines; the `:` separators inside the value are preserved.

---

## 7. Reference parser algorithm (pseudocode)

```
parse_file(path):
  for each logical line:
    skip blank lines
    if first non-space is '#' or ';': skip
    join continuations:
      while line ends with '\' or '\ ':
        line = drop_last_char(line)
        line += read_next_raw_line()
    if line starts with '[':
      current_section = text_between('[', ']')
      continue
    name, value = split at first '='
    name  = trim_one_space(collapse_ws(name))
    value = trim_one_space(collapse_ws(value))
    if no '=': skip
    dispatch(current_section, name, value)

dispatch(section, name, raw_value):
  type = lookup_type(section, name)
  switch type:
    case string:  store raw_value
    case ustring: store upper(raw_value)
    case boolean: store parse_bool(raw_value)
    case enum:    store match_enum(raw_value)
    case list/cmdlist:
        store tokenize_list(raw_value)   # see §3
    case parametric:
        store raw_value

collapse_ws(s): replace runs of whitespace with a single space
trim_one_space(s): remove at most one leading and one trailing space

tokenize_list(s):
  seps = " \t,;\n\r"
  tokens = []
  quoted = false
  current = ""
  i = 0
  # skip leading seps
  while i < len(s) and s[i] in seps: i += 1
  while i < len(s):
    c = s[i]
    if c == '"':
      quoted = not quoted
      i += 1
      continue
    if not quoted and c in seps:
      if current != "": tokens.append(current); current = ""
      i += 1
      while i < len(s) and s[i] in seps: i += 1
      continue
    current += c
    i += 1
  if current != "": tokens.append(current)
  return tokens
```

Important: `tokenize_list` does **not** interpret backslashes. Only the
top-level line reader treats a trailing `\` specially.

---

## 8. Conformance test cases

| Input value | Type | Expected stored value / list |
|---|---|---|
| `"DOMAIN\\administrator"` | cmdlist | `["DOMAIN\\administrator"]` (quotes removed, both backslashes kept) |
| `"a b" c` | cmdlist | `["a b", "c"]` |
| `a,b;c` | cmdlist | `["a","b","c"]` |
| `a\,b` | cmdlist | `["a\","b"]` (backslash literal, comma splits) |
| `"a\"b"` | cmdlist | `["a\b"]` (quote toggles, backslash kept) |
| `'a b'` | cmdlist | `["'a", "b'"]` (single quotes literal) |
| `hello` | string | `hello` |
| `"hello"` | string | `"hello"` (quotes literal) |
| `a  b` | string | `a b` (whitespace collapsed) |
| `x \` + newline + `y` | string | `x y` (continuation) |
| `C:\path\` + newline | string | continuation consumed; parser joins next line |

Note on `"a\"b"`: because backslash is not an escape, the `"` after `\`
toggles quoting off, but the backslash itself is copied literally and `b`
follows with no separator, so the single token is `a\b`. Implementations
must reproduce this, not "fix" it.

---

## 9. Open questions / to verify before implementation

- Confirm the enum token list for `security` and `kerberos method` against
  `lib/param/param_table.c` enum tables.
- Confirm whether `sync machine password to keytab` is `cmdlist` in the
  exact Samba version targeted (it is in current master).
- Confirm behavior of `trim_one_space` with tabs versus spaces; the code uses
  `c_isspace`, so tab counts as whitespace.
