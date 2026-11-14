import copy,os
import pytest
from detect_secrets import SecretsCollection
from detect_secrets.__version__ import VERSION
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.untrusted_baseline import load_untrusted_baseline
from detect_secrets.exceptions import InvalidBaselineError
from detect_secrets.settings import transient_settings,get_settings,get_plugins,get_filters

OLD='AKIAIOSFODNN7EXAMPLE';NEW='AKIAABCDEFGH12345678';TYPE='AWS Access Key'
def record(secret=OLD,line=1,type_=TYPE,**extra):
    return dict(type=type_,hashed_secret=PotentialSecret.hash_secret(secret),line_number=line,**extra)
def candidate(results=None,**extra):return dict(version=VERSION,results=results if results is not None else {'a.env':[record()]},**extra)
def approved(filename='a.env',secret=OLD,type_=TYPE):
    filename=os.path.normpath(filename);out=SecretsCollection();out[filename].add(PotentialSecret(type_,filename,secret,1,is_secret=True,is_verified=False));return out

def test_only_trusted_intersection_authorizes_exemptions():
    base=approved();data=candidate({'a.env':[record(line=99,is_secret=False,is_verified=True),record(NEW)],'b.env':[record()]});original=copy.deepcopy(data)
    result=load_untrusted_baseline(data,base);items=list(result)
    assert len(items)==1;filename,secret=items[0]
    assert filename=='a.env' and secret.is_secret is True and secret.is_verified is False and secret.line_number==99
    assert secret.secret_value is None
    assert data==original and list(base)[0][1].line_number==1
    assert len(load_untrusted_baseline(candidate({'a.env':[record(type_='Other Detector')]}),base))==0

def test_slash_and_backslash_have_same_identity():
    base=approved('cfg/a.env');out=load_untrusted_baseline(candidate({'cfg\\a.env':[record()]}),base)
    assert len(out)==1 and list(out)[0][0].replace('\\','/')=='cfg/a.env'

def test_bad_configuration_never_imports_reads_or_changes_policy(tmp_path,monkeypatch):
    fake=tmp_path/'candidate_plugin.py';marker=tmp_path/'imported.marker';fake.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("ran")\n',encoding='utf8')
    word=tmp_path/'candidate.words';word.write_text('example',encoding='utf8')
    data=candidate(plugins_used=[{'name':'UntrustedPlugin','path':'file://'+str(fake)}],filters_used=[{'path':'file://'+str(fake)+'::filter'},{'path':'detect_secrets.filters.wordlist.should_exclude_secret','file_name':str(word),'min_length':1,'file_hash':'fake'},{'path':'detect_secrets.filters.gibberish.should_exclude_secret','model':str(word),'limit':1}],exclude={'files':'.*','lines':'.*','secrets':'.*'})
    with transient_settings({'plugins_used':[{'name':'AWSKeyDetector'}]}):
        settings=get_settings();before=copy.deepcopy(settings.json());plugins=get_plugins();filters=get_filters();plugin_cache=get_plugins.cache_info();filter_cache=get_filters.cache_info()
        import builtins
        original_open=builtins.open
        def guarded(file,*args,**kwargs):
            if os.fspath(file) in (str(fake),str(word)):raise AssertionError('candidate-controlled path read')
            return original_open(file,*args,**kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(builtins,'open',guarded)
            out=load_untrusted_baseline(data,approved())
        assert len(out)==1 and not marker.exists()
        assert get_plugins.cache_info()==plugin_cache and get_filters.cache_info()==filter_cache
        assert get_settings() is settings and settings.json()==before
        assert get_plugins() is plugins and get_filters() is filters

BAD=[
 lambda d:d.update(version=None),lambda d:d.update(version='not-a-version'),lambda d:d.update(results=[]),
 lambda d:d['results']['a.env'][0].update(hashed_secret='1234'),lambda d:d['results']['a.env'][0].update(hashed_secret='z'*40),
 lambda d:d['results']['a.env'][0].update(line_number=True),lambda d:d['results']['a.env'][0].update(line_number=0),lambda d:d['results']['a.env'][0].update(line_number=-1),
 lambda d:d['results']['a.env'].append(record(line=2)),
 lambda d:d.update(results={'cfg/a.env':[record()],'cfg\\a.env':[record()]}),
]
@pytest.mark.parametrize('mutate',BAD)
def test_invalid_document_has_atomic_failure(mutate):
    data=candidate();mutate(data);before=copy.deepcopy(data);base=approved();approved_before=copy.deepcopy(base.json())
    with pytest.raises(InvalidBaselineError):load_untrusted_baseline(data,base)
    assert data==before and base.json()==approved_before

@pytest.mark.parametrize('path',['../a.env','/a.env','C:\\a.env','C:a.env','\\\\server\\share\\a.env','//server/share/a.env','cfg/../../a.env'])
def test_outside_paths_rejected(path):
    with pytest.raises(InvalidBaselineError):load_untrusted_baseline(candidate({path:[record()]}),approved())

def test_bad_last_record_cannot_change_inputs_or_cache():
    data=candidate({'a.env':[record(),dict(type=TYPE,hashed_secret='bad',line_number=2)]});before=copy.deepcopy(data);base=approved();snapshot=copy.deepcopy(base.json())
    plugins=get_plugins();filters=get_filters();settings=copy.deepcopy(get_settings().json());p=get_plugins.cache_info();f=get_filters.cache_info()
    with pytest.raises(InvalidBaselineError):load_untrusted_baseline(data,base)
    assert get_plugins.cache_info()==p and get_filters.cache_info()==f
    assert data==before and base.json()==snapshot and get_settings().json()==settings
    assert get_plugins() is plugins and get_filters() is filters


def test_real_offline_scan_keeps_candidate_added_credentials(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);(tmp_path/'a.env').write_text('access_key = "'+OLD+'"\nsecond_key = "'+NEW+'"\n',encoding='utf8');(tmp_path/'b.env').write_text('access_key = "'+OLD+'"\n',encoding='utf8')
    with transient_settings({'plugins_used':[{'name':'AWSKeyDetector'}]}):
        fresh=SecretsCollection();fresh.scan_file('a.env');fresh.scan_file('b.env');assert len(fresh)==3
        data=candidate({'a.env':[record(line=30),record(NEW,line=31)],'b.env':[record(line=3)]})
        exemptions=load_untrusted_baseline(data,approved());remaining=fresh-exemptions
        found={(filename.replace('\\','/'),secret.secret_hash) for filename,secret in remaining}
        assert found=={('a.env',PotentialSecret.hash_secret(NEW)),('b.env',PotentialSecret.hash_secret(OLD))}
        assert len(load_untrusted_baseline(candidate({}),approved()))==0
        assert len(load_untrusted_baseline(candidate(),approved()))==1
