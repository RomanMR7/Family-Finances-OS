"""Force ALL legacy default database paths into a disposable test directory."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
production=root/'family_finances_os/data'
output=Path(os.environ.get('FFOS_TEST_OUTPUT',str(root/'artifacts/ui-refresh')))
output.mkdir(parents=True,exist_ok=True)
def fingerprints():
    return {p.name:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns}
            for p in production.glob('family_finances.db*') if p.is_file()}
before=fingerprints()

def production_path(value):
    if not isinstance(value,(str,bytes,os.PathLike)):
        return False
    value=os.fsdecode(value)
    if value.startswith('file:'):
        value=urllib.parse.unquote(value[5:].split('?',1)[0])
    if value==':memory:':
        return False
    return Path(value).resolve().is_relative_to(production.resolve())

def deny_production_mutation(event,args):
    if event=='sqlite3.connect' and production_path(args[0]):
        raise PermissionError('Regression runner forbids opening a production SQLite database')
    if event=='open' and production_path(args[0]):
        mode=args[1] or ''
        flags=args[2] if len(args)>2 and isinstance(args[2],int) else 0
        if any(c in mode for c in 'wax+') or flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            raise PermissionError('Regression runner forbids production database-directory writes')
    if event in ('os.remove','os.rmdir','os.mkdir','os.chmod','os.truncate','os.utime') and production_path(args[0]):
        raise PermissionError('Regression runner forbids production database-directory changes')
    if event in ('os.rename','os.link','os.symlink') and any(production_path(p) for p in args[:2]):
        raise PermissionError('Regression runner forbids production database-directory moves')

sys.addaudithook(deny_production_mutation)
blocked_probes=[]
try:
    with (production/'qa-isolation-write-probe').open('w'):
        raise AssertionError('Production write unexpectedly allowed')
except PermissionError:
    blocked_probes.append('open-write')
import sqlite3
try:
    sqlite3.connect(str(production/'family_finances.db'))
    raise AssertionError('Production SQLite connection unexpectedly allowed')
except PermissionError:
    blocked_probes.append('sqlite-connect')
if '--self-check' in sys.argv:
    print(json.dumps({'blockedProbes':blocked_probes,'productionFilesUnchanged':before==fingerprints()}))
    sys.exit(0)
import family_finances_os.config as config
config.DATA_DIR=Path(tempfile.mkdtemp(prefix='ffos_regression_isolated_'))
config.DB_PATH=config.DATA_DIR/'family_finances.db'
config.ENC_DB_PATH=config.DATA_DIR/'family_finances.db.enc'
config.STRICT_ENCRYPTION=False
from family_finances_os.db import init_database
from family_finances_os.ledger import LedgerEngine
init_database(config.DB_PATH)
ledger=LedgerEngine(conn_or_path=config.DB_PATH)
ledger.seed_default_chart_of_accounts()
ledger.seed_default_categories()
print(f'Isolated legacy fallback DB: {config.DATA_DIR}',flush=True)
suite=unittest.defaultTestLoader.discover(str(root/'family_finances_os'),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=1).run(suite)
after=fingerprints()
proof={'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
       'skipped':len(result.skipped),'successful':result.wasSuccessful(),
       'productionFilesUnchanged':before==after,'before':before,'after':after,
       'auditGuardActive':True,'blockedProbes':blocked_probes,
       'isolatedDataDir':str(config.DATA_DIR)}
(output/'isolated-regression-result.json').write_text(json.dumps(proof,indent=2),encoding='utf-8')
if before!=after:
    print('ERROR: production database fingerprints changed',file=sys.stderr)
sys.exit(0 if result.wasSuccessful() and before==after else 1)
