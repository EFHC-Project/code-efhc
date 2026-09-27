from __future__ import annotations
from fastapi import FastAPI, HTTPException, Request
from .models import CheckRequest, QualityGateResponse
from .security import InputRejected
from .workspace import materialize
from .runners import RUNNERS

app=FastAPI(title='CODE EFHC Quality Gate Runtime',version='0.1.0')

@app.get('/health')
def health():
    return {'status':'ok'}

@app.post('/v1/quality-gate',response_model=QualityGateResponse)
def quality_gate(req:CheckRequest):
    try:
        with materialize(req.files) as root:
            results=[RUNNERS[t](root) for t in req.tools]
    except InputRejected as e:
        raise HTTPException(status_code=400,detail=str(e))
    findings=[f for r in results for f in r.findings]
    statuses={r.status for r in results}
    if 'CONFIG_ERROR' in statuses: status='FAIL_CONFIG'
    elif findings: status='FAIL_FINDINGS'
    elif statuses <= {'PASS'}: status='PASS'
    elif 'ERROR' in statuses: status='ERROR'
    else: status='PARTIAL'
    return QualityGateResponse(status=status,results=results,findings=findings)

@app.post('/mcp')
async def mcp(request:Request):
    body=await request.json()
    method=body.get('method')
    rid=body.get('id')
    if method=='initialize':
        result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'code-efhc-quality-gate','version':'0.1.0'}}
    elif method=='tools/list':
        result={'tools':[{'name':'run_python_quality_gate','description':'Run read-only Flake8, Ruff, mypy and Bandit checks on supplied text files.','inputSchema':{'type':'object','properties':{'files':{'type':'array','items':{'type':'object','properties':{'path':{'type':'string'},'content':{'type':'string'}},'required':['path','content']}}},'required':['files']}}]}
    elif method=='tools/call' and (body.get('params') or {}).get('name')=='run_python_quality_gate':
        args=(body.get('params') or {}).get('arguments') or {}
        req=CheckRequest.model_validate(args)
        out=quality_gate(req)
        result={'content':[{'type':'text','text':out.model_dump_json()}],'structuredContent':out.model_dump()}
    else:
        return {'jsonrpc':'2.0','id':rid,'error':{'code':-32601,'message':'Method not found'}}
    return {'jsonrpc':'2.0','id':rid,'result':result}
