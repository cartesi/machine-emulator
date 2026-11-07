import sys, json, os
from pyrevm import EVM
H = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'harness.json')))
ids = H['ids']
sigs = {'stepOnly': 'stepOnly(bytes32,bytes)', 'resetOnly': 'resetOnly(bytes32,bytes)', 'stepReset': 'stepReset(bytes32,bytes)',
        'send': 'send(bytes32,uint16,bytes32,uint32,bytes32,bytes)', 'bridge': 'bridge(bytes32,uint256,bytes32,bytes)'}
evm = EVM(spec_id="CANCUN")
caller = '0x' + '11' * 20
to = evm.deploy(caller, bytes.fromhex(H['bytecode']), gas=2**40)
def w(h): return h.rjust(64, '0')
def enc(fn, args):
    head, tail, n = '', '', len(args)
    for a in args:
        if a['t'] == 'bytes':
            head += w(hex(n * 32 + len(tail) // 2)[2:])
            hx = a['v']; L = len(hx) // 2
            tail += w(hex(L)[2:]) + hx + '0' * ((64 - len(hx) % 64) % 64)
        elif a['t'] == 'uint': head += w(hex(int(a['v']))[2:])
        else: head += w(a['v'])
    return bytes.fromhex(ids[sigs[fn]] + head + tail)
def decode_err(msg):
    return str(msg)[:200]
stats = {'n': 0, 'bad': 0, 'gasmax': 0}
import random
MUT = int(os.getenv('MUTATE', '0'))
mstats = {'n': 0, 'accepted_same': 0, 'accepted_diff': 0}
def mutate(req, rng):
    args = [dict(a) for a in req['args']]
    pa = [a for a in args if a['t'] == 'bytes'][0]
    hx = pa['v']; b = bytearray.fromhex(hx)
    k = rng.randrange(6)
    if k == 0 and len(b): i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
    elif k == 1: b = b[:max(0, len(b) - rng.choice([1, 8, 31, 32, 64]))]
    elif k == 2: b = b + bytes(rng.choice([1, 8, 32, 64]))
    elif k == 3 and len(b) >= 64:
        i = rng.randrange(len(b) // 32); j = rng.randrange(len(b) // 32)
        bi = b[i*32:i*32+32]; bj = b[j*32:j*32+32]; b[i*32:i*32+32] = bj; b[j*32:j*32+32] = bi
    elif k == 4 and len(b) >= 32:
        i = rng.randrange(len(b) // 32); del b[i*32:i*32+32]
    else:
        i = rng.randrange(len(b) // 32 + 1); b[i*32:i*32] = bytes(32)
    pa['v'] = b.hex()
    return args
for line in sys.stdin:
    if not line.strip(): continue
    req = json.loads(line)
    out = {'id': req['id']}
    try:
        ret = evm.message_call(caller, to, enc(req['fn'], req['args']), gas=req.get('gas', 30000000))
        out['ok'] = True; out['ret'] = ret.hex()
        try: out['gas'] = evm.result.gas_used
        except Exception: pass
    except Exception as e:
        out['ok'] = False; out['err'] = decode_err(e)
    stats['n'] += 1
    if out.get('gas'): stats['gasmax'] = max(stats['gasmax'], out['gas'])
    if MUT and out['ok']:
        rng = random.Random(req['id'])
        for _ in range(MUT):
            margs = mutate(req, rng)
            if margs == req['args']: continue
            mstats['n'] += 1
            try:
                r2 = evm.message_call(caller, to, enc(req['fn'], margs), gas=30000000)
                if r2.hex()[:64] == out['ret'][:64]: mstats['accepted_same'] += 1
                else:
                    mstats['accepted_diff'] += 1
                    print(json.dumps({'MUTANT_ACCEPTED_DIFF': True, 'id': req['id'], 'note': req.get('note'), 'ret': r2.hex()[:64], 'honest': out['ret'][:64]}), flush=True)
            except Exception: pass
    if 'exp' in req:
        exp = req['exp']; got = out['ret'][:64] if out['ok'] else None
        if (exp is None and out['ok']) or (exp is not None and got != exp):
            stats['bad'] += 1
            out.update({'MISMATCH': True, 'exp': exp, 'fn': req['fn'], 'note': req.get('note')})
            print(json.dumps(out), flush=True)
    else:
        print(json.dumps(out), flush=True)
print(json.dumps({'SUMMARY': stats, 'mut': mstats}), flush=True)
