import pytest
from detect_secrets import SecretsCollection
from detect_secrets.__version__ import VERSION
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.untrusted_baseline import load_untrusted_baseline
from detect_secrets.exceptions import InvalidBaselineError

def test_explicit_null_is_not_a_positive_line_number():
    approved=SecretsCollection()
    secret=PotentialSecret('AWS Access Key','app.env','AKIAIOSFODNN7EXAMPLE',1)
    approved['app.env'].add(secret)
    candidate={'version':VERSION,'results':{'app.env':[{'type':secret.type,'hashed_secret':secret.secret_hash,'line_number':None}]}}
    with pytest.raises(InvalidBaselineError):
        load_untrusted_baseline(candidate,approved)
