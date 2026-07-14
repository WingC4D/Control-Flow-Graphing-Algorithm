import re, iced_x86
from iced_x86 import Decoder, Formatter, FormatterSyntax
fmt = Formatter(FormatterSyntax.INTEL)
line_re = re.compile(r'^#\s*(\w+)\s+@0x([0-9a-fA-F]+)\s+((?:0x[0-9a-fA-F]{2}\s*)+)$')
root_re = re.compile(r"Analyzing (\S+?)'s Root Block")
blk_re  = re.compile(r'Analyzing.*Block|Analyzing.*Root')
PATH='D:/DevEnv/Cpp_Projects/ControlFlowGraph/Test.log'

instrs=[]; cur_fn='?'
with open(PATH, encoding='utf-16-le') as f:
    for lineno, raw in enumerate(f,1):
        s=raw.strip()
        rm=root_re.search(s)
        if rm: 
            cur_fn=rm.group(1)
        if blk_re.search(s): 
            continue
        m=line_re.match(s)
        if not m: 
            continue
        instrs.append((lineno,cur_fn,int(m.group(2),16),
                       bytes(int(b,16) for b in m.group(3).split())))
print(f"parsed {len(instrs)} instruction lines across functions")

lm=[]; df=[]
from collections import Counter
bad_fns=Counter()
for (lineno,fn,addr,bs) in instrs:

    pl=len(bs); d=Decoder(64,bs,ip=addr)
    if d.can_decode:
        ins=d.decode()
        if ins.is_invalid : 
            df.append((lineno,fn,hex(addr),bs.hex(' '),pl)); bad_fns[fn]+=1
        elif ins.len!=pl:
            try: t=fmt.format(ins)
            except: t='?'
            lm.append((lineno,fn,hex(addr),bs.hex(' '),pl,ins.len,t)); bad_fns[fn]+=1
    else: df.append((lineno,fn,hex(addr),bs.hex(' '),pl)); bad_fns[fn]+=1

print(f"\n=== LENGTH MISMATCHES: {len(lm)} ===")
for x in lm[:60]: print(f"  L{x[0]} [{x[1]}] @{x[2]}: printed={x[4]} true={x[5]}  {x[6]:26s} [{x[3]}]")
print(f"\n=== DECODE FAILURES: {len(df)} ===")
for x in df[:60]: print(f"  L{x[0]} [{x[1]}] @{x[2]}: {x[4]}B  [{x[3]}]")
print(f"\n=== FUNCTIONS WITH ANY MISMATCH: {len(bad_fns)} ===")
for fn,c in bad_fns.most_common(): print(f"  {fn}: {c}")