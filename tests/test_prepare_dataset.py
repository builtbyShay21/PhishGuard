import os
import pandas as pd
import pytest
from argparse import Namespace
from scripts.prepare_dataset import prepare_dataset

def create_args(benign=None, phishing=None, input_files=None, url_col=None, output="out.csv", meta="meta.csv"):
    return Namespace(
        benign=benign,
        phishing=phishing,
        input=input_files,
        output=output,
        metadata=meta,
        url_column=url_col
    )

def test_prepare_dataset_benign_phishing_args(tmp_path, capsys):
    b_csv = tmp_path / "benign.csv"
    p_csv = tmp_path / "phish.csv"
    out_csv = tmp_path / "features.csv"
    meta_csv = tmp_path / "meta.csv"
    
    # Benign uses 'website', Phish uses 'uri'
    pd.DataFrame({"website": ["example.com", "test.com"]}).to_csv(b_csv, index=False)
    pd.DataFrame({"uri": ["http://phish.com", "example.com"]}).to_csv(p_csv, index=False)
    
    args = create_args(benign=[str(b_csv)], phishing=[str(p_csv)], output=str(out_csv), meta=str(meta_csv))
    prepare_dataset(args)
    
    # 'example.com' is in both, so it's a cross-class conflict. 
    # Valid urls remaining: test.com (benign), phish.com (phish)
    
    df = pd.read_csv(out_csv)
    meta = pd.read_csv(meta_csv)
    
    assert len(df) == 2
    assert "url" not in df.columns
    assert "label" in df.columns
    
    assert len(meta) == 2
    assert "url" in meta.columns
    assert "normalized_url" in meta.columns
    assert "source" in meta.columns
    
    captured = capsys.readouterr()
    assert "Cross-class conflicts removed: 1" in captured.out
    assert "Final benign samples: 1" in captured.out
    assert "Final phishing samples: 1" in captured.out

def test_prepare_dataset_ambiguous_column(tmp_path):
    csv = tmp_path / "ambiguous.csv"
    pd.DataFrame({"url": ["example.com"], "domain": ["test.com"]}).to_csv(csv, index=False)
    
    args = create_args(benign=[str(csv)])
    with pytest.raises(ValueError, match="Multiple possible URL columns found"):
        prepare_dataset(args)

def test_prepare_dataset_explicit_column(tmp_path, capsys):
    csv = tmp_path / "explicit.csv"
    # Column is random_col
    pd.DataFrame({"random_col": ["example.com"]}).to_csv(csv, index=False)
    
    args = create_args(benign=[str(csv)], url_col="random_col", output=str(tmp_path / "out.csv"))
    prepare_dataset(args)
    captured = capsys.readouterr()
    assert "Final benign samples: 1" in captured.out

def test_prepare_dataset_normalized_duplicate(tmp_path, capsys):
    csv = tmp_path / "dups.csv"
    # Raw strings differ but normalized URL is the same
    pd.DataFrame({
        "url": ["example.com", "https://example.com", "  example.com  "],
        "label": [0, 0, 0]
    }).to_csv(csv, index=False)
    
    args = create_args(input_files=[str(csv)], output=str(tmp_path / "out.csv"))
    prepare_dataset(args)
    
    captured = capsys.readouterr()
    assert "Duplicates removed: 2" in captured.out
    assert "Final benign samples: 1" in captured.out
