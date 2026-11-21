import unittest, tempfile, json, base64, importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('followup', ROOT/'payload_analyzer.py')
a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
def dec(s): return base64.b64decode(s).decode()
class FollowupTests(unittest.TestCase):
 def test_module_list(self):
  for encoded, expected in MODULES:
   result=a.analyze([{'node_id':0,'value':dec(encoded)}])
   self.assertEqual(expected, result['category']==a.CATEGORIES[1])
 def test_arithmetic(self):
  for encoded in ARITHMETIC:
   result=a.analyze([{'node_id':0,'value':dec(encoded)}])
   self.assertIn(dec(RULE),result['rule_ids'])
   if encoded == ARITHMETIC[0]:
    self.assertTrue(result['summary'].startswith("This payload's purpose is to test whether injected SQL is evaluated by pairing the always-true condition"))
    self.assertIn('division-by-zero error',result['summary'])
   if encoded == ARITHMETIC[3]:
    conditional=a.analyze([{'node_id':0,'value':dec(encoded)+'=1'}])
    description=next(t['description'] for t in conditional['techniques'] if t['rule_id']==dec(RULE))
    self.assertIn('condition 1=1 is false',description)
  self.assertNotEqual(a.CATEGORIES[0], a.analyze([{'node_id':0,'value':dec(BENIGN)}])['category'])
 def test_filtered_containers(self):
  scratch=Path('E:/Temp/payload-analyzer'); scratch.mkdir(parents=True,exist_ok=True)
  with tempfile.TemporaryDirectory(dir=scratch) as folder:
   for suffix in ('.json','.json.pax'):
    out=Path(folder)/('report'+suffix)
    self.assertEqual(0,a.main([str(FIXTURE),'-o',str(out)]))
    filtered=out.with_name('report.determined'+suffix)
    with a.paxio.open_text_in(filtered) as stream: report=json.load(stream)
    self.assertNotIn('unmatched',report)
    self.assertEqual('determined_only',report['meta']['filter'])
    self.assertTrue(report['units'])
    self.assertEqual(len(report['units']), report['meta']['units_emitted'])
    self.assertTrue(all(u['analysis_status']=='analysed' and u['analysis']['category'] in ('sqli', 'rce', 'file_access') for u in report['units']))
 def test_disabled(self):
  with tempfile.TemporaryDirectory(dir='E:/Temp/payload-analyzer') as folder:
   out=Path(folder)/'report.json'
   self.assertEqual(0,a.main([str(FIXTURE),'-o',str(out),'--no-determined-output']))
   self.assertFalse(out.with_name('report.determined.json').exists())

MODULES=[('ZXh0LlN0YXRleHBBY2NvcmRpb24sU3RhdGV4cEFydGljbGVGb3JtYXRlclJldmFtcCxTdGF0ZXhwQlBNLFN0YXRleHBDb2xsZWN0aW9uLFN0YXRleHBEeW5hbWljQ2hhcnRzLFN0YXRleHBHbG9zc2FyeVRvb2xUaXAsU3RhdGV4cEludGVyYWN0aXZlTWFwLFN0YXRleHBUT0MsU3RhdGV4cFZpc1Rvb2wsc3RhdGV4cGVkaXR3YXJuaW5nfGpxdWVyeSxvb2pzLG9vanMtdWktY29yZSxvb2pzLXVpLXdpZGdldHMsc2l0ZXxqcXVlcnkuY2xpZW50LHVpfG1lZGlhd2lraS5TdHJpbmcsVGl0bGUsYXBpLGJhc2UsY2xkcixjb29raWUsanF1ZXJ5TXNnLGxhbmd1YWdlLHRvYyx1c2VyLHV0aWx8bWVkaWF3aWtpLmxpYnMucGx1cmFscnVsZXBhcnNlcnxtZWRpYXdpa2kucGFnZS5tZWRpYSxyZWFkeXxtZWRpYXdpa2kuc2tpbm5pbmcuY29udGVudC5wYXJzb2lkfG9vanMtdWktY29yZS5pY29ucyxzdHlsZXN8b29qcy11aS13aWRnZXRzLmljb25zfG9vanMtdWkuc3R5bGVzLmluZGljYXRvcnN8c2tpbnMuc3RhdGV4cHJldmFtcA==', False), ('eHxpZA==', True), ('MTI3LjAuMC4xfHBpbmcgLW4gMSBob3N0', True)]
ARITHMETIC=['MT0xIEFORCAxLzA9MQ==', 'bi8w', 'MS8oU0VMRUNUIDAp', 'MS8oQ0FTRSBXSEVOIDE9MSBUSEVOIDEgRUxTRSAwIEVORCk=', 'MS8oMT0wKQ==', 'RVhQKDcxMCk=', 'RVhQKH4wKQ==', 'Q09OVkVSVChJTlQsJ2FiYycp']
RULE='c3FsaS5lcnJvcl9iYXNlZC5kaXZpZGVfYnlfemVybw=='
BENIGN='cmF0aW89MS8y'
FIXTURE=ROOT/'tests/fixtures/assessor_output.json.gz'
