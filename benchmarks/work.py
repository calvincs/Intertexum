"""Measure admission friction independently of embedding inference."""
import json
import platform
import statistics
import time
from pathlib import Path

from agentmesh.pow import Issuer, solve


def main():
    result={'hardware':platform.platform(),'python':platform.python_version(),
            'method':'fresh random challenge per trial; single Python solver; 2s client budget',
            'settings':[]}
    for bits,count in ((0,16),(12,32),(16,64),(18,32)):
        issuer=Issuer('a'*64,'work-benchmark',bits)
        solve_ms=[];verify_ms=[];attempts=[];timeouts=0
        for _ in range(count):
            ticket=issuer.issue('b'*64,'c'*64)
            start=time.perf_counter()
            try:
                nonce=solve(ticket)
            except ValueError:
                timeouts+=1
                continue
            solve_ms.append((time.perf_counter()-start)*1000)
            start=time.perf_counter();issuer.verify(ticket,nonce,'b'*64,'c'*64)
            verify_ms.append((time.perf_counter()-start)*1000);attempts.append(nonce+1)
        result['settings'].append({'bits':bits,'trials':count,'timeouts':timeouts,
            'solve_ms_p50':statistics.median(solve_ms),'solve_ms_p95':sorted(solve_ms)[int(.95*(len(solve_ms)-1))],
            'solve_ms_max':max(solve_ms),'verify_ms_p50':statistics.median(verify_ms),
            'attempts_mean':statistics.mean(attempts),'solve_samples_ms':solve_ms})
    outfile=Path(__file__).parent/'results/work.json'
    outfile.parent.mkdir(parents=True,exist_ok=True)
    outfile.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({**result,'settings':[{k:v for k,v in x.items() if k!='solve_samples_ms'} for x in result['settings']]},indent=2))


if __name__=='__main__':main()
