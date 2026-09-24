import os
import json
import pandas as pd
from scripts.audit_dataset import extended_audit

def test_extended_audit_end_to_end(tmp_path):
    p_csv = tmp_path / "p.csv"
    pd.DataFrame({
        "url": ["http://phish.com"],
        "status": ["phishing"]
    }).to_csv(p_csv, index=False)
    
    out_json = tmp_path / "out.json"
    
    extended_audit(str(p_csv), None, str(out_json))
    
    assert os.path.exists(out_json)
    
    with open(out_json) as f:
        data = json.load(f)
        assert data['phishing_count'] == 1
        assert data['legitimate_count'] == 0
