import os
import pandas as pd
from collections import Counter

BINARY_TO_DNA = {
    "00": "A", "01": "T", "10": "G", "11": "C"
}

def binary_to_dna(binary_data: str) -> str:
    return ''.join(BINARY_TO_DNA[binary_data[i:i+2]] for i in range(0, len(binary_data), 2))

def extract_kmers(dna_sequence: str, k: int) -> Counter:
    return Counter(dna_sequence[i:i+k] for i in range(len(dna_sequence) - k + 1))

def process_file(filepath: str, k: int) -> Counter:
    try:
        with open(filepath, 'rb') as file:
            binary_data = ''.join(f"{byte:08b}" for byte in file.read(1024 * 1024))  # Read first 1MB
        dna_sequence = binary_to_dna(binary_data)
        return extract_kmers(dna_sequence, k)
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return Counter()

def append_to_csv(kmer_counts: Counter, label: int, all_kmers: list, output_csv: str):
    feature_vector = {kmer: kmer_counts.get(kmer, 0) for kmer in all_kmers}
    feature_vector['label'] = label
    df = pd.DataFrame([feature_vector])
    df.to_csv(output_csv, mode='a', header=not os.path.exists(output_csv), index=False)

def generate_all_kmers(k: int) -> list:
    from itertools import product
    return [''.join(p) for p in product('ATGC', repeat=k)]

def process_dataset(base_dir: str, benign_dir: str, k: int, output_csv: str):
    all_kmers = generate_all_kmers(k)
    if os.path.exists(output_csv):
        os.remove(output_csv)

    # Loop through ransomware and benign folders
    for folder, label in [(base_dir, 1), (benign_dir, 0)]:
        if not folder:
            print(f"Skipping empty folder: {folder}")
            continue
        print(f"Processing folder: {folder} (Label: {label})")
        for root, _, files in os.walk(folder):  # Use os.walk for full traversal
            for file in files:
                filepath = os.path.join(root, file)
                if os.path.isfile(filepath):
                    print(f"Processing file: {filepath}")
                    kmer_counts = process_file(filepath, k)
                    append_to_csv(kmer_counts, label, all_kmers, output_csv)
                else:
                    print(f"Skipped non-file item: {filepath}")

# Parameters
base_dir = "./datasets/ransomwares"
benign_dir = "./datasets/benign"
k = 7
output_csv = f"./feature_datasets/ransomware_dna{k}.csv"

process_dataset(base_dir, benign_dir, k, output_csv)
