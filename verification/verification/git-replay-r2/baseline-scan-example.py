import os,socket,tempfile
from pathlib import Path
from detect_secrets import SecretsCollection
from detect_secrets.__version__ import VERSION
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.untrusted_baseline import load_untrusted_baseline
from detect_secrets.settings import transient_settings

def no_network(*args,**kwargs):raise RuntimeError("Network disabled for local example")
socket.socket=no_network
old="AKIAIOSFODNN7EXAMPLE";new="AKIAABCDEFGH12345678"
original=os.getcwd()
with tempfile.TemporaryDirectory(prefix="baseline-scan-",dir=os.environ["TEMP"]) as temp:
 os.chdir(temp)
 try:
  Path("app.env").write_text('access_key = "'+old+'"\n')
  with transient_settings({"plugins_used":[{"name":"AWSKeyDetector"}]}):
   approved=SecretsCollection();approved.scan_file("app.env")
   assert len(approved)==1
   Path("app.env").write_text('access_key = "'+old+'"\nother_key = "'+new+'"\n')
   Path("copy.env").write_text('access_key = "'+old+'"\n')
   fresh=SecretsCollection();fresh.scan_file("app.env");fresh.scan_file("copy.env")
   def record(value,line):return {"type":"AWS Access Key","hashed_secret":PotentialSecret.hash_secret(value),"line_number":line}
   candidate={"version":VERSION,"results":{"app.env":[record(old,99),record(new,100)],"copy.env":[record(old,1)]},"plugins_used":[{"name":"AttackerOwnedPlugin","path":"file://not-loaded.py"}],"exclude":{"files":".*"}}
   exemptions=load_untrusted_baseline(candidate,approved);alerts=fresh-exemptions
   print("Credential scan using trusted built-in detector")
   print("Approved old findings:",len(approved))
   print("Fresh findings:",len(fresh))
   print("Candidate-authorized exemptions:",len(exemptions))
   print("Alerts retained:",len(alerts))
   assert len(fresh)==3 and len(exemptions)==1 and len(alerts)==2
   print("New credential and copied credential: both still reported")
   print("Candidate plugin and exclude settings: not applied")
 finally:os.chdir(original)
