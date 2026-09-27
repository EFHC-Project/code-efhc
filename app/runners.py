from __future__ import annotations
import json, re, shutil, subprocess
from pathlib import Path
from .models import Finding, ToolResult

TIMEOUT=60

def _version(cmd):
    try:
        p=subprocess.run(cmd, text=True, capture_output=True, timeout=10)
        return (p.stdout or p.stderr).strip().splitlines()[0][:200]
    except Exception:
        return None

def _run(tool, cmd, root:Path):
    exe=shutil.which(cmd[0])
    if not exe:
        return None
    try:
        return subprocess.run(cmd,cwd=root,text=True,capture_output=True,timeout=TIMEOUT)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd,124,e.stdout or '',e.stderr or 'timeout')

def run_flake8(root:Path):
    p=_run('flake8',['flake8','.'],root)
    if p is None: return ToolResult(tool='flake8',status='TOOL_UNAVAILABLE')
    finds=[]
    rx=re.compile(r'^(.*?):(\d+):(\d+):\s+([A-Z]\d+)\s+(.*)$')
    for line in p.stdout.splitlines():
        m=rx.match(line)
        if m: finds.append(Finding(tool='flake8',path=m[1],line=int(m[2]),column=int(m[3]),code=m[4],message=m[5]))
    status='PASS' if p.returncode==0 else ('FINDINGS' if finds else 'CONFIG_ERROR')
    return ToolResult(tool='flake8',status=status,exit_code=p.returncode,version=_version(['flake8','--version']),findings=finds,stderr=p.stderr[-4000:])

def run_ruff(root:Path):
    p=_run('ruff',['ruff','check','.','--output-format','json'],root)
    if p is None: return ToolResult(tool='ruff',status='TOOL_UNAVAILABLE')
    finds=[]
    try:
        data=json.loads(p.stdout or '[]')
        for x in data:
            loc=x.get('location') or {}
            finds.append(Finding(tool='ruff',path=x.get('filename',''),line=loc.get('row'),column=loc.get('column'),code=x.get('code'),message=x.get('message','')))
    except Exception:
        data=[]
    status='PASS' if p.returncode==0 else ('FINDINGS' if finds else 'CONFIG_ERROR')
    return ToolResult(tool='ruff',status=status,exit_code=p.returncode,version=_version(['ruff','--version']),findings=finds,stderr=p.stderr[-4000:])

def run_mypy(root:Path):
    p=_run('mypy',['mypy','.','--show-column-numbers','--show-error-codes','--no-error-summary'],root)
    if p is None: return ToolResult(tool='mypy',status='TOOL_UNAVAILABLE')
    finds=[]
    rx=re.compile(r'^(.*?):(\d+):(\d+):\s+error:\s+(.*?)\s+\[([^\]]+)\]$')
    for line in p.stdout.splitlines():
        m=rx.match(line)
        if m: finds.append(Finding(tool='mypy',path=m[1],line=int(m[2]),column=int(m[3]),code=m[5],message=m[4]))
    status='PASS' if p.returncode==0 else ('FINDINGS' if finds else 'CONFIG_ERROR')
    return ToolResult(tool='mypy',status=status,exit_code=p.returncode,version=_version(['mypy','--version']),findings=finds,stderr=p.stderr[-4000:])

def run_bandit(root:Path):
    p=_run('bandit',['bandit','-r','.','-f','json','-q'],root)
    if p is None: return ToolResult(tool='bandit',status='TOOL_UNAVAILABLE')
    finds=[]
    try:
        data=json.loads(p.stdout or '{}')
        for x in data.get('results',[]):
            finds.append(Finding(tool='bandit',path=x.get('filename',''),line=x.get('line_number'),column=x.get('col_offset'),code=x.get('test_id'),message=x.get('issue_text',''),severity=x.get('issue_severity'),confidence=x.get('issue_confidence')))
    except Exception:
        data={}
    status='PASS' if p.returncode==0 else ('FINDINGS' if finds else 'CONFIG_ERROR')
    return ToolResult(tool='bandit',status=status,exit_code=p.returncode,version=_version(['bandit','--version']),findings=finds,stderr=p.stderr[-4000:])

RUNNERS={'flake8':run_flake8,'ruff':run_ruff,'mypy':run_mypy,'bandit':run_bandit}
