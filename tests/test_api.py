import unittest
from fastapi.testclient import TestClient
from app.server import app

class ApiTests(unittest.TestCase):
    def setUp(self): self.c=TestClient(app)
    def test_health(self): self.assertEqual(self.c.get('/health').json(),{'status':'ok'})
    def test_mcp_list(self):
        r=self.c.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['result']['tools'][0]['name'],'run_python_quality_gate')
    def test_quality_gate_contract(self):
        r=self.c.post('/v1/quality-gate',json={'files':[{'path':'a.py','content':'x=1\n'}]})
        self.assertEqual(r.status_code,200)
        self.assertEqual(len(r.json()['results']),4)
if __name__=='__main__': unittest.main()
