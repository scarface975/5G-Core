#!/usr/bin/env python3
"""Generate the C NGAP schema (libs/ngap/src/schema.c, include/g5c/ngap_ids.h) from the pinned TS 38.413 ASN.1 modules.

The generated tables drive a generic APER codec (libs/ngap/src/aper.c); decoded PDUs are JSON trees.

  python tools/gen_ngap_c.py            (repo root; reads docs/specs/asn1/*.asn)

Supported ASN.1 subset (all that NGAP uses): BOOLEAN, NULL, INTEGER, ENUMERATED, BIT STRING, OCTET STRING (incl.
CONTAINING), PrintableString/VisibleString/UTF8String, OBJECT IDENTIFIER, SEQUENCE (with extension marker and
additions), SEQUENCE OF, CHOICE, and the parameterised protocol containers (IE containers, extension containers,
single containers, container lists) resolved against the NGAP-PROTOCOL-IES / -EXTENSION / -PRIVATE-IES object sets.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASN = ROOT / "docs" / "specs" / "asn1"
# NGAP-Containers is not parsed: its parameterised containers are built into the codec (see parse_container)
MODULES = ["NGAP-CommonDataTypes", "NGAP-Constants", "NGAP-IEs", "NGAP-PDU-Contents", "NGAP-PDU-Descriptions"]

# ---------------------------------------------------------------- tokenizer
TOKEN = re.compile(r"""\s*(?:
    (?P<comment>--[^\n]*)
  | (?P<assign>::=)
  | (?P<ellipsis>\.\.\.)
  | (?P<range>\.\.)
  | (?P<ident>&?[A-Za-z][A-Za-z0-9\-]*)
  | (?P<num>-?\d+)
  | (?P<sym>[{}()\[\],|;:@<>])
)""", re.X)


def tokenize(text):
    pos, out = 0, []
    text = text.replace("\r", "")
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise SystemExit(f"tokenizer stuck near: {text[pos:pos+60]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "comment":
            continue
        out.append(m.group(kind))
    return out


class P:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def next(self):
        v = self.t[self.i]
        self.i += 1
        return v

    def eat(self, v):
        if self.peek() == v:
            self.i += 1
            return True
        return False

    def expect(self, v):
        got = self.next()
        if got != v:
            raise SystemExit(f"expected {v!r}, got {got!r} near {' '.join(self.t[max(0,self.i-8):self.i+6])}")


# ---------------------------------------------------------------- model
types = {}       # name -> ast
consts = {}      # name -> int
ie_sets = {}     # set name -> list of dict(id, crit, presence, type)
procs = {}       # object name -> dict
proc_sets = {}   # set name -> [object names]
anon = [0]
CLASSES = {"NGAP-PROTOCOL-IES", "NGAP-PROTOCOL-IES-PAIR", "NGAP-PROTOCOL-EXTENSION", "NGAP-PRIVATE-IES", "NGAP-ELEMENTARY-PROCEDURE"}


def value_of(tok):
    if re.fullmatch(r"-?\d+", tok):
        return int(tok)
    if tok in consts:
        return consts[tok]
    if tok == "MAX":
        return None
    raise SystemExit(f"unknown constant {tok}")


def parse_bound_list(p):
    """Inside ( ... ): returns dict(lb, ub, ext, containing) for INTEGER/SIZE constraints."""
    r = {"lb": None, "ub": None, "ext": False, "containing": None}
    p.expect("(")
    if p.eat("SIZE"):
        p.expect("(")
        parse_range(p, r)
        p.expect(")")
    elif p.peek() == "CONTAINING":
        p.next()
        r["containing"] = parse_type(p)
    else:
        parse_range(p, r)
    p.expect(")")
    return r


def parse_range(p, r):
    """One value or range, or a union (a..b | c | d): PER uses the smallest and largest value of the union."""
    lows, highs = [], []
    has_lb = has_ub = True
    while True:
        a = p.next()
        lo = None if a == "MIN" else value_of(a)
        if a == "MIN":
            has_lb = False
        if p.eat(".."):
            b = p.next()
            hi = None if b == "MAX" else value_of(b)
            if b == "MAX":
                has_ub = False
        else:
            hi = lo
        lows.append(lo)
        highs.append(hi)
        if not p.eat("|"):
            break
    r["has_lb"], r["has_ub"] = has_lb, has_ub
    r["lb"] = min(x for x in lows if x is not None) if has_lb else None
    r["ub"] = max(x for x in highs if x is not None) if has_ub else None
    if p.eat(","):
        p.expect("...")
        r["ext"] = True
        while p.peek() not in (")",):  # ignore extension additions of the constraint
            p.next()


def skip_braces(p):
    depth = 0
    while True:
        t = p.next()
        if t == "{":
            depth += 1
        elif t == "}":
            depth -= 1
            if depth == 0:
                return


def parse_container(name, p):
    """name followed by '{' ... '}' parameters."""
    p.expect("{")
    node = {"kind": "container", "container": name}
    if name in ("ProtocolIE-ContainerList", "ProtocolIE-ContainerPairList"):
        lo = p.next()
        p.expect(",")
        hi = p.next()
        p.expect(",")
        node["lb"], node["ub"] = value_of(lo), value_of(hi)
    if name == "PrivateIE-Container" and p.peek() == "}":
        p.next()
        return {"kind": "container", "container": name, "set": None}
    if name in ("ProtocolIE-Container", "ProtocolIE-ContainerPair") and p.peek() == "}":
        p.next()
        return {"kind": "container", "container": name, "set": None}
    p.expect("{")
    node["set"] = p.next()
    p.expect("}")
    p.expect("}")
    return node


CONTAINERS = {"ProtocolIE-Container", "ProtocolIE-SingleContainer", "ProtocolExtensionContainer", "PrivateIE-Container",
              "ProtocolIE-ContainerList", "ProtocolIE-ContainerPair", "ProtocolIE-ContainerPairList"}


def parse_type(p):
    t = p.next()
    if t == "BOOLEAN":
        return {"kind": "bool"}
    if t == "NULL":
        return {"kind": "null"}
    if t == "OBJECT":
        p.expect("IDENTIFIER")
        return {"kind": "oid"}
    if t == "INTEGER":
        n = {"kind": "int", "lb": None, "ub": None, "has_lb": False, "has_ub": False, "ext": False}
        if p.peek() == "(":
            n.update(parse_bound_list(p))
        return n
    if t == "ENUMERATED":
        p.expect("{")
        names, ext_at = [], None
        while not p.eat("}"):
            if p.eat("..."):
                ext_at = len(names)
            else:
                names.append(p.next())
                if p.peek() == "(":  # explicit number: not used by NGAP
                    raise SystemExit("explicit enumeration values unsupported")
            p.eat(",")
        return {"kind": "enum", "names": names, "nroot": len(names) if ext_at is None else ext_at, "ext": ext_at is not None}
    if t == "BIT":
        p.expect("STRING")
        n = {"kind": "bits", "lb": None, "ub": None, "ext": False}
        if p.peek() == "(":
            n.update(parse_bound_list(p))
        return n
    if t == "OCTET":
        p.expect("STRING")
        n = {"kind": "octets", "lb": None, "ub": None, "ext": False, "containing": None}
        if p.peek() == "(":
            n.update(parse_bound_list(p))
        return n
    if t in ("PrintableString", "VisibleString", "UTF8String", "IA5String"):
        n = {"kind": "str", "strkind": t, "lb": None, "ub": None, "ext": False}
        if p.peek() == "(":
            n.update(parse_bound_list(p))
        return n
    if t == "SEQUENCE":
        if p.peek() == "{":
            return parse_fields(p, "seq")
        r = {"lb": None, "ub": None, "ext": False}
        if p.peek() == "(":
            r = parse_bound_list(p)
        p.expect("OF")
        elem = parse_type(p)
        return {"kind": "seqof", "elem": elem, "lb": r.get("lb"), "ub": r.get("ub"), "ext": r["ext"]}
    if t == "CHOICE":
        return parse_fields(p, "choice")
    if t in CONTAINERS:
        return parse_container(t, p)
    if t.startswith("PROCMSG-"):
        return {"kind": "procmsg", "which": {"PROCMSG-InitiatingMessage": 0, "PROCMSG-SuccessfulOutcome": 1,
                                             "PROCMSG-UnsuccessfulOutcome": 2}[t]}
    # reference to a named type; a trailing constraint on a reference is not used by NGAP
    return {"kind": "ref", "name": t}


def parse_fields(p, kind):
    p.expect("{")
    fields, ext_at = [], None
    while not p.eat("}"):
        if p.eat("..."):
            ext_at = len(fields)
        elif p.peek() == "[" and p.peek(1) == "[":
            raise SystemExit("extension addition groups unsupported")
        else:
            name = p.next()
            ty = parse_type(p)
            optional = False
            if p.eat("OPTIONAL"):
                optional = True
            elif p.peek() == "DEFAULT":
                raise SystemExit("DEFAULT unsupported")
            fields.append({"name": name, "type": ty, "optional": optional})
        p.eat(",")
    nroot = len(fields) if ext_at is None else ext_at
    return {"kind": kind, "fields": fields, "nroot": nroot, "ext": ext_at is not None}


def parse_ie_entry(p, cls):
    """{ ID x CRITICALITY y TYPE/EXTENSION T PRESENCE z }"""
    p.expect("{")
    e = {}
    while not p.eat("}"):
        k = p.next()
        if k == "ID":
            e["id"] = p.next()
        elif k == "CRITICALITY":
            e["crit"] = p.next()
        elif k in ("TYPE", "EXTENSION"):
            e["type"] = parse_type(p)
        elif k == "PRESENCE":
            e["presence"] = p.next()
        else:
            raise SystemExit(f"unexpected {k} in IE entry")
    return e


def parse_object_set(name, cls, p):
    p.expect("{")
    entries, refs = [], []
    while not p.eat("}"):
        t = p.peek()
        if t == "{":
            if cls in ("NGAP-PROTOCOL-IES", "NGAP-PROTOCOL-EXTENSION", "NGAP-PRIVATE-IES", "NGAP-PROTOCOL-IES-PAIR"):
                entries.append(parse_ie_entry(p, cls))
            else:
                skip_braces(p)
        elif t == "...":
            p.next()
        elif t in ("|", ","):
            p.next()
        else:
            refs.append(p.next())
    if cls == "NGAP-ELEMENTARY-PROCEDURE":
        proc_sets[name] = refs
    else:
        ie_sets[name] = entries


def parse_procedure_object(name, p):
    p.expect("{")
    o = {"name": name, "crit": "ignore"}
    while not p.eat("}"):
        k = p.next()
        if k == "INITIATING":
            p.expect("MESSAGE")
            o["init"] = p.next()
        elif k == "SUCCESSFUL":
            p.expect("OUTCOME")
            o["succ"] = p.next()
        elif k == "UNSUCCESSFUL":
            p.expect("OUTCOME")
            o["unsucc"] = p.next()
        elif k == "PROCEDURE":
            p.expect("CODE")
            o["code"] = p.next()
        elif k == "CRITICALITY":
            o["crit"] = p.next()
        else:
            raise SystemExit(f"unexpected {k} in procedure object")
    procs[name] = o


def parse_module(text):
    p = P(tokenize(text))
    # header: Name { ... } DEFINITIONS AUTOMATIC TAGS ::= BEGIN
    while p.next() != "BEGIN":
        pass
    while p.peek() is not None and p.peek() != "END":
        if p.peek() == "IMPORTS":
            while p.next() != ";":
                pass
            continue
        name = p.next()
        nxt = p.peek()
        if nxt == "::=":
            p.next()
            if p.peek() == "CLASS":
                p.next()
                skip_braces(p)  # { fields }
                if p.peek() == "WITH":
                    p.next()
                    p.expect("SYNTAX")
                    skip_braces(p)
                continue
            types[name] = parse_type(p)
        elif nxt == "{":
            # parameterised type definition (NGAP-Containers): skipped, containers are built in
            p.next()
            depth = 1
            while depth:
                t = p.next()
                depth += (t == "{") - (t == "}")
            p.expect("::=")
            # skip the body: up to the next assignment head (Name ... ::=) is hard; bodies are single types: parse it
            parse_type(p)
        else:
            # value / object / object set:  name Type ::= ...
            cls = p.next()
            if cls == "OBJECT" and p.peek() == "IDENTIFIER":
                raise SystemExit("OID value assignment unsupported")
            p.expect("::=")
            if cls in CLASSES and name[0].isupper():
                parse_object_set(name, cls, p)
            elif cls == "NGAP-ELEMENTARY-PROCEDURE":
                parse_procedure_object(name, p)
            elif cls in CLASSES:
                parse_object_set(name, cls, p)
            else:
                consts[name] = value_of(p.next())


# ---------------------------------------------------------------- resolution + emission
def cname(n):
    return "T_" + re.sub(r"[^A-Za-z0-9]", "_", n)


def crit(c):
    return {"reject": 0, "ignore": 1, "notify": 2}[c]


def pres(c):
    return {"optional": 0, "conditional": 1, "mandatory": 2}[c]


def cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


out_types = []     # (cname, struct body) in definition order
emitted = {}


def emit_type(ast, hint):
    """Return the C name of a type node for `ast`, emitting it (and its children) if needed."""
    if ast["kind"] == "ref":
        if ast["name"] not in types:
            raise SystemExit(f"unresolved type {ast['name']}")
        return emit_named(ast["name"])
    anon[0] += 1
    n = f"{cname(hint)}_{anon[0]}"
    define(n, ast, hint)
    return n


def emit_named(name):
    cn = cname(name)
    if cn in emitted:
        return cn
    emitted[cn] = True
    ast = types[name]
    if ast["kind"] == "ref":  # alias
        target = emit_named(ast["name"])
        out_types.append((cn, f".kind = NG_ALIAS, .alias = &{target}, .name = {cstr(name)}"))
        return cn
    define(cn, ast, name, named=True)
    return cn


def bounds(ast):
    lbv, ubv = ast.get("lb"), ast.get("ub")
    span = (ubv - (lbv if lbv is not None else 0)) if ubv is not None else 0
    ubc = min(ubv, 2**63 - 1) if ubv is not None else 0
    f = [f".has_lb = {1 if lbv is not None else 0}, .has_ub = {1 if ubv is not None else 0}",
         f".lb = {lbv if lbv is not None else 0}LL, .ub = {ubc}LL, .span = {span}ULL",
         f".ext = {1 if ast.get('ext') else 0}"]
    return ", ".join(f)


def define(cn, ast, hint, named=False):
    k = ast["kind"]
    name = f".name = {cstr(hint if named else '')}"
    if k == "bool":
        body = f".kind = NG_BOOL, {name}"
    elif k == "null":
        body = f".kind = NG_NULL, {name}"
    elif k == "oid":
        body = f".kind = NG_OID, {name}"
    elif k == "int":
        body = f".kind = NG_INT, {name}, {bounds(ast)}"
    elif k == "enum":
        arr = f"{cn}_names"
        out_types.append((arr, None, "static const char *const " + arr + "[] = {" + ", ".join(cstr(x) for x in ast["names"]) + "};"))
        body = f".kind = NG_ENUM, {name}, .names = {arr}, .nnames = {len(ast['names'])}, .nroot = {ast['nroot']}, .ext = {1 if ast['ext'] else 0}"
    elif k == "bits":
        body = f".kind = NG_BITS, {name}, {bounds(ast)}"
    elif k == "octets":
        extra = ""
        if ast.get("containing"):
            c = emit_type(ast["containing"], hint + "_c")
            extra = f", .contained = &{c}"
        body = f".kind = NG_OCTETS, {name}, {bounds(ast)}{extra}"
    elif k == "str":
        sk = {"PrintableString": 0, "VisibleString": 1, "UTF8String": 2, "IA5String": 3}[ast["strkind"]]
        body = f".kind = NG_STR, {name}, .strkind = {sk}, {bounds(ast)}"
    elif k == "seqof":
        e = emit_type(ast["elem"], hint + "_e")
        body = f".kind = NG_SEQOF, {name}, .elem = &{e}, {bounds(ast)}"
    elif k in ("seq", "choice"):
        fs = []
        for i, f in enumerate(ast["fields"]):
            ft = emit_type(f["type"], f"{hint}_{f['name']}")
            fs.append(f"{{{cstr(f['name'])}, &{ft}, {1 if f['optional'] else 0}}}")
        arr = f"{cn}_fields"
        if not fs:
            fs = ["{\"\", NULL, 0}"]
        out_types.append((arr, None, "static const ngap_field " + arr + "[] = {" + ", ".join(fs) + "};"))
        kind = "NG_SEQ" if k == "seq" else "NG_CHOICE"
        body = f".kind = {kind}, {name}, .fields = {arr}, .nfields = {len(ast['fields'])}, .nroot = {ast['nroot']}, .ext = {1 if ast['ext'] else 0}"
    elif k == "procmsg":
        body = f".kind = NG_PROCMSG, {name}, .strkind = {ast['which']}"
    elif k == "container":
        cont = {"ProtocolIE-Container": "NG_IE_CONTAINER", "ProtocolIE-SingleContainer": "NG_IE_SINGLE",
                "ProtocolExtensionContainer": "NG_EXT_CONTAINER", "PrivateIE-Container": "NG_PRIVATE_CONTAINER",
                "ProtocolIE-ContainerList": "NG_IE_LIST", "ProtocolIE-ContainerPair": "NG_IE_PAIR_CONTAINER",
                "ProtocolIE-ContainerPairList": "NG_IE_PAIR_LIST"}[ast["container"]]
        s = ast.get("set")
        sref = f", .set = &SET_{re.sub(r'[^A-Za-z0-9]', '_', s)}" if s else ""
        lbub = f", .has_lb = 1, .has_ub = 1, .lb = {ast['lb']}LL, .ub = {ast['ub']}LL, .span = {ast['ub'] - ast['lb']}ULL" if "lb" in ast else ""
        body = f".kind = {cont}, {name}{sref}{lbub}"
        if s:
            need_set(s, cont == "NG_EXT_CONTAINER")
    else:
        raise SystemExit(f"cannot emit kind {k}")
    out_types.append((cn, body))


needed_sets = {}


def need_set(s, ext):
    needed_sets[s] = ext


def main():
    for m in MODULES:
        text = (ASN / f"{m}.asn").read_text(encoding="utf8")
        if m == "NGAP-PDU-Descriptions":
            # the three PDU wrappers use information-object-class field references; the codec resolves them by
            # procedure code, so they are replaced by markers
            text = re.sub(r"(InitiatingMessage|SuccessfulOutcome|UnsuccessfulOutcome)\s*::=\s*SEQUENCE\s*\{.*?[\n]\}",
                          lambda mo: f"{mo.group(1)} ::= PROCMSG-{mo.group(1)}", text, flags=re.S)
        parse_module(text)
    # constants referenced by id-* in sets
    # resolve NGAP-PDU
    root = emit_named("NGAP-PDU")
    # InitiatingMessage/SuccessfulOutcome/UnsuccessfulOutcome contain open types resolved by procedure code; the
    # codec special-cases those three named types, so their field list is replaced by a marker.
    pdu_choice = types["NGAP-PDU"]
    # procedures
    class1 = [x for s in proc_sets.get("NGAP-ELEMENTARY-PROCEDURES-CLASS-1", []) for x in [s]]
    class2 = [x for s in proc_sets.get("NGAP-ELEMENTARY-PROCEDURES-CLASS-2", []) for x in [s]]
    plist = []
    for name in class1 + class2:
        o = procs[name]
        row = {"code": value_of(o["code"]), "crit": crit(o["crit"]), "name": name[0].upper() + name[1:]}
        for key in ("init", "succ", "unsucc"):
            row[key] = emit_named(o[key]) if key in o else None
        plist.append(row)
    # IE sets
    set_defs = []
    done = set()
    while True:
        todo = [s for s in needed_sets if s not in done]
        if not todo:
            break
        for s in todo:
            done.add(s)
            entries = ie_sets.get(s)
            if entries is None:
                raise SystemExit(f"unresolved IE set {s}")
            rows = []
            for e in entries:
                ty = emit_type(e["type"], f"{s}_{e['id']}")
                rows.append(f"{{{value_of(e['id'])}, {crit(e.get('crit', 'ignore'))}, {pres(e.get('presence', 'optional'))}, {cstr(e['id'].replace('id-', '', 1))}, &{ty}}}")
            set_defs.append((s, rows))

    w = []
    w.append("/* @generated by tools/gen_ngap_c.py from docs/specs/asn1 (3GPP TS 38.413). DO NOT EDIT. */")
    w.append('#include "g5c/ngap.h"')
    w.append("")
    for item in out_types:
        if item[1] is not None:
            w.append(f"extern const ngap_type {item[0]};")
    for s, _ in set_defs:
        w.append(f"extern const ngap_ie_set SET_{re.sub(r'[^A-Za-z0-9]', '_', s)};")
    w.append("")
    for item in out_types:
        if item[1] is None:
            w.append(item[2])
    w.append("")
    for s, rows in set_defs:
        sn = re.sub(r"[^A-Za-z0-9]", "_", s)
        w.append(f"static const ngap_ie_def DEFS_{sn}[] = {{{', '.join(rows) if rows else '{0, 0, 0, \"\", NULL}'}}};")
        w.append(f"const ngap_ie_set SET_{sn} = {{DEFS_{sn}, {len(rows)}}};")
    w.append("")
    for item in out_types:
        if item[1] is not None:
            w.append(f"const ngap_type {item[0]} = {{{item[1]}}};")
    w.append("")
    w.append(f"const ngap_type *const NGAP_PDU_TYPE = &{root};")
    w.append("const ngap_named NGAP_NAMED[] = {")
    for tname in sorted(types):
        if cname(tname) in emitted:
            w.append(f"    {{{cstr(tname)}, &{cname(tname)}}},")
    w.append("};")
    w.append(f"const size_t NGAP_NNAMED = {sum(1 for t in types if cname(t) in emitted)};")
    w.append("const ngap_proc NGAP_PROCS[] = {")
    for r in plist:
        def ref(x):
            return f"&{x}" if x else "NULL"
        w.append(f"    {{{r['code']}, {r['crit']}, {cstr(r['name'])}, {ref(r['init'])}, {ref(r['succ'])}, {ref(r['unsucc'])}}},")
    w.append("};")
    w.append(f"const size_t NGAP_NPROCS = {len(plist)};")
    (ROOT / "libs" / "ngap" / "src" / "schema.c").write_text("\n".join(w) + "\n", encoding="utf8", newline="\n")

    # id constants header
    h = ["/* @generated by tools/gen_ngap_c.py from docs/specs/asn1/NGAP-Constants.asn. DO NOT EDIT. */",
         "#ifndef G5C_NGAP_IDS_H", "#define G5C_NGAP_IDS_H", ""]
    for name, val in consts.items():
        if name.startswith("id-"):
            ident = re.sub(r"[^A-Za-z0-9]", "_", name[3:])
            kind = "PROC" if name in {v["code"] for v in procs.values()} else "IE"
            h.append(f"#define NGAP_{kind}_{ident} {val}")
    h += ["", "#endif", ""]
    (ROOT / "libs" / "ngap" / "include" / "g5c" / "ngap_ids.h").write_text("\n".join(h), encoding="utf8", newline="\n")
    print(f"{len(out_types)} schema objects, {len(set_defs)} IE sets, {len(plist)} procedures")


if __name__ == "__main__":
    main()
