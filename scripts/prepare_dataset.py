import os
import argparse
import pandas as pd
from typing import List
from src.url_validator import normalize_and_validate_url
from src.feature_extractor import URLFeatureExtractor

def find_url_column(df, explicit_col=None):
    if explicit_col:
        if explicit_col in df.columns:
            return explicit_col
        raise ValueError(f"Explicit URL column '{explicit_col}' not found in {list(df.columns)}.")
    
    matches = [col for col in df.columns if str(col).lower() in {"url", "uri", "domain", "website"}]
    
    if len(matches) == 0:
        raise ValueError(f"No URL column found in {list(df.columns)}. Please specify --url-column.")
    elif len(matches) > 1:
        raise ValueError(f"Multiple possible URL columns found: {matches}. Please specify --url-column.")
    
    return matches[0]

def load_file(file_path, assigned_label, source_name, url_col):
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return pd.DataFrame()
        
    df = pd.read_csv(file_path)
    if df.empty:
        return pd.DataFrame()
        
    col = find_url_column(df, url_col)
    
    if assigned_label is None:
        if 'label' not in df.columns:
            raise ValueError(f"No label column found in {file_path}, and no class specified.")
        df_out = df[[col, 'label']].copy()
    else:
        df_out = df[[col]].copy()
        df_out['label'] = assigned_label
        
    df_out.rename(columns={col: 'raw_url'}, inplace=True)
    df_out['source'] = source_name
    return df_out

def prepare_dataset(args):
    dfs = []
    
    if args.benign:
        for f in args.benign:
            dfs.append(load_file(f, 0, "benign_source", args.url_column))
            
    if args.phishing:
        for f in args.phishing:
            dfs.append(load_file(f, 1, "phishing_source", args.url_column))
            
    if args.input:
        for f in args.input:
            dfs.append(load_file(f, None, "mixed_source", args.url_column))
            
    if not dfs:
        print("[-] No valid data loaded.")
        return

    combined_df = pd.concat(dfs, ignore_index=True)
    if combined_df.empty:
        print("[-] Dataset is empty.")
        return

    initial_len = len(combined_df)
    
    # Clean labels
    combined_df['label'] = pd.to_numeric(combined_df['label'], errors='coerce')
    combined_df.dropna(subset=['label'], inplace=True)
    combined_df = combined_df[combined_df['label'].isin([0, 1])]
    combined_df['label'] = combined_df['label'].astype(int)
    
    raw_benign = len(combined_df[combined_df['label'] == 0])
    raw_phishing = len(combined_df[combined_df['label'] == 1])

    # Clean missing / empty URLs
    combined_df.dropna(subset=['raw_url'], inplace=True)
    combined_df['raw_url'] = combined_df['raw_url'].astype(str).str.strip()
    combined_df = combined_df[combined_df['raw_url'] != ""]

    valid_rows = []
    invalid_removed = initial_len - len(combined_df)

    # Normalize URLs
    for _, row in combined_df.iterrows():
        try:
            norm_url = normalize_and_validate_url(row['raw_url'])
            valid_rows.append({
                'raw_url': row['raw_url'],
                'normalized_url': norm_url,
                'label': row['label'],
                'source': row['source']
            })
        except Exception:
            invalid_removed += 1

    norm_df = pd.DataFrame(valid_rows)
    if norm_df.empty:
        print("[-] No valid URLs found.")
        return

    # Cross-class duplicate protection
    conflict_urls_series = norm_df.groupby('normalized_url')['label'].nunique()
    conflict_urls = conflict_urls_series[conflict_urls_series > 1].index.tolist()
    cross_class_conflicts_removed = len(conflict_urls)
    
    norm_df = norm_df[~norm_df['normalized_url'].isin(conflict_urls)]

    # Normalized duplicate detection
    len_before_dedup = len(norm_df)
    norm_df.drop_duplicates(subset=['normalized_url'], inplace=True)
    duplicates_removed = len_before_dedup - len(norm_df)

    processed_features = []
    processed_metadata = []

    for _, row in norm_df.iterrows():
        norm_url = row['normalized_url']
        label = row['label']
        
        extractor = URLFeatureExtractor(norm_url)
        features = extractor.extract_features()
        
        feature_row = {}
        for k, v in features.items():
            feature_row[k] = int(v) if isinstance(v, bool) else v
        feature_row['label'] = label
        processed_features.append(feature_row)
        
        processed_metadata.append({
            'url': row['raw_url'],
            'normalized_url': norm_url,
            'label': label,
            'source': row['source']
        })

    if not processed_features:
        print("[-] No valid URLs were processed after filtering.")
        return

    features_df = pd.DataFrame(processed_features)
    
    # Shuffle reproducibly
    features_df = features_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    features_df.to_csv(args.output, index=False)
    
    if args.metadata:
        metadata_df = pd.DataFrame(processed_metadata)
        metadata_df = metadata_df.iloc[features_df.index]
        meta_dir = os.path.dirname(args.metadata)
        if meta_dir:
            os.makedirs(meta_dir, exist_ok=True)
        metadata_df.to_csv(args.metadata, index=False)
        
    final_benign = (features_df['label'] == 0).sum()
    final_phishing = (features_df['label'] == 1).sum()
    total_final = len(features_df)
    
    print("\nPHISHGUARD DATASET PREPARATION")
    print("-" * 30)
    print(f"Raw benign URLs: {raw_benign}")
    print(f"Raw phishing URLs: {raw_phishing}")
    print(f"Invalid URLs removed: {invalid_removed}")
    print(f"Duplicates removed: {duplicates_removed}")
    print(f"Cross-class conflicts removed: {cross_class_conflicts_removed}")
    print(f"\nFinal benign samples: {final_benign}")
    print(f"Final phishing samples: {final_phishing}")
    print(f"Total final samples: {total_final}")
    print(f"Benign percentage: {(final_benign / total_final) * 100:.1f}%")
    print(f"Phishing percentage: {(final_phishing / total_final) * 100:.1f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare PhishGuard ML Dataset")
    parser.add_argument("-b", "--benign", nargs="+", help="Input CSV files containing benign URLs")
    parser.add_argument("-p", "--phishing", nargs="+", help="Input CSV files containing phishing URLs")
    parser.add_argument("-i", "--input", nargs="+", help="Input CSV files containing mixed URLs (must have a 'label' column)")
    parser.add_argument("-o", "--output", required=True, help="Output processed features CSV file")
    parser.add_argument("-m", "--metadata", help="Output metadata CSV file (contains raw and normalized URLs)")
    parser.add_argument("--url-column", help="Explicitly specify the column name containing URLs")
    
    args = parser.parse_args()
    if not (args.benign or args.phishing or args.input):
        parser.error("At least one input source (--benign, --phishing, or --input) must be provided.")
        
    prepare_dataset(args)
