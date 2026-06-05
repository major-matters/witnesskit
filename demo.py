"""
TrailKit v0 - narrated demo. Run: cd python && PYTHONPATH=. python3 ../demo.py
"""
import copy, json
from trailkit import Chain, generate_keypair, verify_chain

LINE = "-" * 72
def show(t): print(f"\n{LINE}\n{t}\n{LINE}")

show("1. An agent does some things; each action is signed and chained")
key, pub = generate_keypair()
trail = Chain(key, actor="agent-7")
trail.append("tool_call", {"tool": "search", "query": "running shoes"})
trail.append("decision",  {"approved": True, "mandate": "shoes < $500"})
trail.append("payment",   {"merchant": "Fleet Feet", "amount": 240, "currency": "USD"})
for e in trail.entries:
    print(f"  #{e['seq']}  {e['action']:<10} hash {e['hash'][:12]}…  prev {str(e['prev_hash'])[:12]}…")

show("2. Export the evidence pack and verify it (pinned to the agent's key)")
pack = trail.to_json()
v = verify_chain(pack, trusted_keys=[pub])
print(f"  decision: {v['valid']}  ·  {v['length']} entries  ·  {v['reason']}")

show("3. Someone quietly flips the 'approved' decision after the fact")
tampered = copy.deepcopy(pack)
tampered["entries"][1]["payload"]["approved"] = False
v = verify_chain(tampered, trusted_keys=[pub])
print(f"  decision: {v['valid']}  ·  broken at entry #{v['broken_at']}  ·  {v['reason']}")

show("4. An attacker forges a whole clean chain with their OWN key")
atk_key, _ = generate_keypair()
forged = Chain(atk_key, actor="agent-7")
forged.append("payment", {"merchant": "Attacker Inc", "amount": 1_000_000, "currency": "USD"})
v = verify_chain(forged.to_json(), trusted_keys=[pub])   # still pinned to the real agent
print(f"  decision: {v['valid']}  ·  broken at entry #{v['broken_at']}  ·  {v['reason']}")

show("5. What an evidence-pack entry looks like")
print("\n".join("  " + ln for ln in json.dumps(pack["entries"][2], indent=2).splitlines()))

print(f"\n{LINE}\nTrailKit v0: sign + chain every action, detect any tamper, locate it.\n{LINE}")
