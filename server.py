#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,re,threading,time,uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib import request as urlrequest
from urllib.error import URLError,HTTPError

VERSION="1.0.0"; MAX_PAYLOAD=1048576; CHUNK_BYTES=65536; MAX_WORKERS=4; RATE=30
TOKEN=os.getenv("REVIEW_TOKEN","development-token"); START=time.monotonic()
RULES=[
 ("MOCK-001","critical","security","eval usage",lambda x:"eval(" in x),
 ("MOCK-002","critical","security","hardcoded credential",lambda x:bool(re.search(r"(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}['\"]",x,re.I))),
 ("MOCK-003","high","security","SQL string concatenation",lambda x:bool(re.search(r"['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+|\+\s*['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b",x,re.I))),
 ("MOCK-005","medium","correctness","loose null comparison",lambda x:bool(re.search(r"(?:==|!=)\s*null\b",x))),
 ("MOCK-006","medium","performance","deep-clone via JSON",lambda x:"JSON.parse(JSON.stringify(" in x),
 ("MOCK-007","low","style","console.log left in",lambda x:"console.log(" in x),
 ("MOCK-008","low","style","unresolved marker",lambda x:"TODO" in x or "FIXME" in x),
 ("MOCK-INJ","critical","security","prompt-injection content",lambda x:bool(re.search(r"ignore previous instructions|disregard all prior|you are now",x,re.I)))]
class InvalidDiff(ValueError): pass
def parse_diff(diff):
 lines=diff.splitlines(); files=[]; cur=None; n=None; hunks=False
 if not any(x.startswith("--- ") for x in lines) or not any(x.startswith("+++ ") for x in lines): raise InvalidDiff("diff must be a unified diff")
 for raw in lines:
  if raw.startswith("+++ "):
   path=raw[4:].strip().split("\t",1)[0]; path=path[2:] if path.startswith("b/") else path
   cur={"path":"unknown" if path=="/dev/null" else path,"raw":[raw],"added":[]}; files.append(cur); n=None; continue
  if not cur: continue
  cur["raw"].append(raw); m=re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@",raw)
  if m: n=int(m.group(1)); hunks=True
  elif n is not None:
   if raw.startswith("+") and not raw.startswith("+++"): cur["added"].append((n,raw[1:])); n+=1
   elif raw.startswith("-") or raw.startswith("\\ No newline"): pass
   else: n+=1
 if not files or not hunks: raise InvalidDiff("diff must contain a unified hunk")
 return files
def chunks(files):
 count=size=0
 for f in files:
  num=len(("\n".join(f["raw"])+"\n").encode())
  if size and size+num>CHUNK_BYTES: count+=1; size=0
  if num>CHUNK_BYTES: count+=1
  else: size+=num
 return count+(1 if size else 0)
def scan(files):
 out=[]
 for f in files:
  for line,text in f["added"]:
   for rule in RULES:
    if rule[4](text):
     rid,severity,category,title,_=rule; out.append({"id":f"{rid}:{f['path']}:{line}","ruleId":rid,"path":f["path"],"line":line,"severity":severity,"category":category,"title":title,"evidence":text})
  added=f["added"]
  for i,(line,text) in enumerate(added):
   match=re.search(r"\bcatch\s*(?:\([^)]*\))?\s*\{",text)
   if match:
    parts=[text[match.end():].strip()]
    for _,later in added[i+1:]:
     parts.append(later.strip())
     if "}" in later: break
    compact=" ".join(parts).replace("}","").strip()
    if not compact or re.fullmatch(r"(?:(?://.*)|(?:/\*.*?\*/))*",compact): out.append({"id":f"MOCK-004:{f['path']}:{line}","ruleId":"MOCK-004","path":f["path"],"line":line,"severity":"high","category":"correctness","title":"swallowed exception","evidence":text})
 return sorted({x["id"]:x for x in out}.values(),key=lambda x:(x["path"],x["line"],x["ruleId"]))
class Store:
 def __init__(self): self.jobs={}; self.ids={}; self.cache={}; self.times=deque(); self.lock=threading.RLock(); self.pool=ThreadPoolExecutor(MAX_WORKERS)
 def allowed(self):
  with self.lock:
   now=time.monotonic()
   while self.times and now-self.times[0]>=60:self.times.popleft()
   if len(self.times)>=RATE:return False,max(1,int(61-(now-self.times[0])))
   self.times.append(now); return True,0
 def create(self,body,raw,key):
  # Idempotency is deliberately over received bytes. Cache identity is only
  # diff/options: unknown request fields are specified to be ignored.
  idem=hashlib.sha256(raw).hexdigest()
  canonical=json.dumps({"diff":body["diff"],"options":body.get("options",{})},separators=(",",":"),ensure_ascii=False).encode()
  fp=hashlib.sha256(canonical).hexdigest()
  with self.lock:
   if key and key in self.ids:
    old,jid=self.ids[key]
    return (None,"conflict") if old!=idem else (self.jobs[jid],"existing")
   jid=uuid.uuid4().hex; source=self.cache.get(fp)
   if source and source["status"]=="done":
    usage=dict(source["usage"]);usage["cacheHit"]=True; findings=source["findings"]
    events=[("status",{"status":"queued"})]+[("finding",x) for x in findings]+[("status",{"status":"done"}),("done",{"total":len(findings),"usage":usage})]
    job={"jobId":jid,"status":"done","findings":findings,"usage":usage,"events":events,"cond":threading.Condition(self.lock)}
   else:
    job={"jobId":jid,"status":"queued","findings":[],"usage":None,"events":[("status",{"status":"queued"})],"cond":threading.Condition(self.lock),"body":body,"fp":fp}
   self.jobs[jid]=job
   if key:self.ids[key]=(idem,jid)
   if job["status"]=="queued":self.pool.submit(self.run,jid)
   return job,"new"
 def emit(self,j,event,data):j["events"].append((event,data));j["cond"].notify_all()
 def run(self,jid):
  with self.lock:j=self.jobs[jid];j["status"]="running";self.emit(j,"status",{"status":"running"})
  try:
   b=j["body"]; files=parse_diff(b["diff"]); opt=b.get("options") or {}; provider=opt.get("provider","mock"); limit=opt.get("maxFindings",100)
   if not isinstance(limit,int) or isinstance(limit,bool) or limit<0:raise ValueError("maxFindings must be a non-negative integer")
   findings=scan(files) if provider=="mock" else self.llm(b["diff"])
   usage={"inputBytes":len(b["diff"].encode()),"chunks":chunks(files),"cacheHit":False};findings=findings[:limit]
   with self.lock:
    j["findings"]=findings;j["usage"]=usage;j["status"]="done"
    for x in findings:self.emit(j,"finding",x)
    self.emit(j,"status",{"status":"done"});self.emit(j,"done",{"total":len(findings),"usage":usage});self.cache[j["fp"]]=j
  except Exception as e:
   with self.lock:j["status"]="failed";j["error"]=str(e)[:500];self.emit(j,"status",{"status":"failed","error":j["error"]})
 def llm(self,diff):
  base,key=os.getenv("LLM_BASE_URL"),os.getenv("LLM_API_KEY")
  if not base or not key:raise RuntimeError("llm provider is not configured (set LLM_BASE_URL and LLM_API_KEY)")
  data=json.dumps({"model":os.getenv("LLM_MODEL","gpt-4o-mini"),"messages":[{"role":"user","content":"Review this diff: "+diff}]}).encode(); req=urlrequest.Request(base.rstrip("/")+"/chat/completions",data=data,headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
  try:
   with urlrequest.urlopen(req,timeout=25) as r:json.load(r)
  except (URLError,HTTPError,TimeoutError) as e:raise RuntimeError("llm provider unavailable: "+str(e))
  return []
STORE=Store()
class Handler(BaseHTTPRequestHandler):
 protocol_version="HTTP/1.1"
 def log_message(self,*args):pass
 def respond(self,code,obj,headers={}):
  data=json.dumps(obj,separators=(",",":")).encode();self.send_response(code);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(data)))
  for k,v in headers.items():self.send_header(k,str(v))
  self.end_headers();self.wfile.write(data)
 def fail(self,status,code,msg,headers={}):self.respond(status,{"error":{"code":code,"message":msg}},headers)
 def auth(self):
  if self.headers.get("Authorization")!="Bearer "+TOKEN:self.fail(401,"unauthorized","missing or invalid bearer token");return False
  return True
 def do_GET(self):
  if self.path=="/health":return self.respond(200,{"status":"ok","version":VERSION,"uptimeSeconds":round(time.monotonic()-START,3)})
  if self.path=="/spec":return self.respond(200,{"specVersion":"1.0","providers":["mock","llm"],"limits":{"maxPayloadBytes":MAX_PAYLOAD,"chunkBytes":CHUNK_BYTES,"maxConcurrentJobs":MAX_WORKERS,"rateLimitPerMinute":RATE}})
  if not self.path.startswith("/v1/"):return self.fail(404,"not_found","route not found")
  if not self.auth():return
  m=re.fullmatch(r"/v1/reviews/([\w-]+)(/stream)?",self.path)
  if not m:return self.fail(404,"not_found","route not found")
  with STORE.lock:j=STORE.jobs.get(m.group(1))
  if not j:return self.fail(404,"not_found","job not found")
  if m.group(2):return self.stream(j)
  out={k:j[k] for k in ("jobId","status")}
  if j["status"]=="done":out.update(findings=j["findings"],usage=j["usage"])
  if j["status"]=="failed":out["error"]=j.get("error","job failed")
  return self.respond(200,out)
 def do_POST(self):
  if self.path!="/v1/reviews":return self.fail(404,"not_found","route not found")
  if not self.auth():return
  ok,retry=STORE.allowed()
  if not ok:return self.fail(429,"rate_limited","rate limit exceeded",{"Retry-After":retry})
  try:n=int(self.headers.get("Content-Length","-1"))
  except ValueError:n=-1
  if n>MAX_PAYLOAD:return self.fail(413,"payload_too_large","payload exceeds 1 MiB")
  raw=self.rfile.read(max(0,n))
  if len(raw)>MAX_PAYLOAD:return self.fail(413,"payload_too_large","payload exceeds 1 MiB")
  try:b=json.loads(raw)
  except (ValueError,UnicodeDecodeError):return self.fail(400,"invalid_json","request body is not valid JSON")
  if not isinstance(b,dict) or not isinstance(b.get("diff"),str) or not b["diff"].strip():return self.fail(422,"invalid_diff","diff is required")
  try:parse_diff(b["diff"])
  except InvalidDiff as e:return self.fail(422,"invalid_diff",str(e))
  opt=b.get("options",{})
  if not isinstance(opt,dict) or opt.get("provider","mock") not in ("mock","llm"):return self.fail(422,"invalid_diff","invalid review options")
  j,state=STORE.create(b,raw,self.headers.get("Idempotency-Key"))
  if state=="conflict":return self.fail(409,"idempotency_conflict","key was used with a different request body")
  self.respond(202,{"jobId":j["jobId"],"status":"queued"})
 def stream(self,j):
  self.send_response(200);self.send_header("Content-Type","text/event-stream");self.send_header("Cache-Control","no-cache");self.send_header("Connection","close");self.end_headers();at=0
  while True:
   with STORE.lock:
    events=list(j["events"]);done=j["status"] in ("done","failed")
    if at>=len(events) and not done:j["cond"].wait(20);continue
   for event,data in events[at:]:self.wfile.write((f"event: {event}\ndata: "+json.dumps(data,separators=(",",":"))+"\n\n").encode());self.wfile.flush()
   at=len(events)
   if done:return
if __name__=="__main__":
 port=int(os.getenv("PORT","8080"));print(f"listening on :{port}",flush=True);ThreadingHTTPServer(("0.0.0.0",port),Handler).serve_forever()
