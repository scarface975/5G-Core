"""Shared by the generators of the SBI producers (tools/spec/gen_udr_api.py, tools/spec/gen_nssf_api.py): the pinned OpenAPI files, loaded, and
the schemas reachable from the operations flattened to a compact pool that libs/oaschema validates against.

A pool entry is a JSON-schema subset as a plain dict (type, nullable, enum, ranges, lengths, pattern, items, required, properties,
additionalProperties, allOf / anyOf / oneOf); a reference to another schema becomes {"$": <index>}. Unresolvable references (a
specification that is not pinned) become the empty schema, which accepts anything, and are listed in `unresolved`."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
OA = ROOT / "docs" / "specs" / "src" / "openapi"
KEEP_NUM = ("minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties")


APP = "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml"
# Where the text of a specification overrules the pattern of its own OpenAPI file: (file, schema, member, array of the type). Nothing is edited in
# docs/specs; the generators apply these to what they read. TS 29.519 6.2.6.2.2 / 6.2.6.2.3 (NOTE: "for the Traffic Influence Data applies to any UE,
# the internalGroupId is set to AnyUE") needs "AnyUE" where the file types the member as GroupId, whose pattern is a group identifier.
ANY_UE = [(APP, "TrafficInfluData", "interGroupId", False), (APP, "TrafficInfluDataPatch", "interGroupId", False),
          (APP, "TrafficInfluSub", "internalGroupIds", True)]


def norm(n):
    return re.sub(r"[^a-z0-9]", "", n.lower().replace(".yaml", ""))


class Pool:
    def __init__(self, aliases=None):
        self.aliases = aliases or {}
        self.files = {}
        for p in sorted(OA.glob("*.yaml")):
            try:
                self.files[p.name] = yaml.safe_load(p.read_text(encoding="utf8").replace("\t", "  "))
            except Exception:  # an extraction artefact in a file we do not need
                pass
        for f, sch, member, is_arr in ANY_UE:
            node = (((self.files.get(f) or {}).get("components") or {}).get("schemas") or {}).get(sch, {}).get("properties", {}).get(member)
            if node is None:
                continue
            target = node["items"] if is_arr else node
            alt = {"anyOf": [{"type": "string", "enum": ["AnyUE"]}, {k: v for k, v in target.items() if k != "description"}]}
            if is_arr:
                node["items"] = alt
            else:
                node.clear()
                node.update(alt)
        self.unresolved = set()
        self.pool = []
        self.ix = {}  # "file:pointer" -> index

    def find(self, name):
        if name in self.files:
            return name
        if norm(name) in self.aliases:
            return self.aliases[norm(name)]
        n = norm(name)
        for f in self.files:
            if norm(f) == n:
                return f
        for f in self.files:
            if norm(f).startswith(n) or n.startswith(norm(f)):
                return f
        return None

    @staticmethod
    def resolve_ptr(doc, ptr):
        cur = doc
        for part in ptr.lstrip("#/").split("/"):
            if part == "":
                continue
            cur = cur[part.replace("~1", "/").replace("~0", "~")]
        return cur

    def simplify(self, node, cur_file):
        if not isinstance(node, dict):
            return {}
        if "$ref" in node:
            ref = node["$ref"]
            fpart, _, ptr = ref.partition("#")
            fname = cur_file if fpart == "" else self.find(fpart)
            if fname is None:
                self.unresolved.add(ref)
                return {}
            key = f"{fname}:{ptr}"
            if key not in self.ix:
                self.ix[key] = len(self.pool)
                self.pool.append(None)
                try:
                    target = self.resolve_ptr(self.files[fname], ptr)
                except (KeyError, TypeError):
                    self.unresolved.add(ref)
                    target = {}
                self.pool[self.ix[key]] = self.simplify(target, fname)
            return {"$": self.ix[key]}
        out = {}
        if node.get("type"):
            out["type"] = node["type"]
        if node.get("nullable"):
            out["nullable"] = True
        for k in KEEP_NUM:
            if k in node and isinstance(node[k], (int, float)):
                out[k] = node[k]
        for k in ("pattern", "enum"):
            if k in node:
                out[k] = node[k]
        if isinstance(node.get("required"), list):
            out["required"] = node["required"]
        if isinstance(node.get("properties"), dict):
            out["properties"] = {k: self.simplify(v, cur_file) for k, v in node["properties"].items()}
        ap = node.get("additionalProperties")
        if isinstance(ap, dict):
            out["additionalProperties"] = self.simplify(ap, cur_file)
        elif ap is False:
            out["additionalProperties"] = False
        if "items" in node:
            out["items"] = self.simplify(node["items"], cur_file)
        for comb in ("oneOf", "anyOf", "allOf"):
            if isinstance(node.get(comb), list):
                out[comb] = [self.simplify(x, cur_file) for x in node[comb]]
        return out

    def schema_id(self, node, cur_file):
        """Pool index of a schema (a $ref or inline), -1 for none."""
        if node is None:
            return -1
        s = self.simplify(node, cur_file)
        if list(s.keys()) == ["$"]:
            return s["$"]
        self.pool.append(s)
        return len(self.pool) - 1

    def named(self, fname, name):
        """Pool index of #/components/schemas/<name> of a file."""
        return self.schema_id({"$ref": f"#/components/schemas/{name}"}, fname)

    def is_array(self, ix):
        seen = 0
        while ix >= 0 and seen < 20:
            node = self.pool[ix]
            if "$" in node:
                ix = node["$"]
                seen += 1
                continue
            return node.get("type") == "array"
        return False
