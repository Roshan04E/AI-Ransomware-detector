import os
import hashlib
import logging
import aiofiles
from pathlib import Path
from typing import List, Dict
from joblib import load
import pandas as pd
from collections import Counter
import math
import asyncio
from assets.VTIsMalicious import check_file

# DNA binary translation
BINARY_TO_DNA = {
    "00": "A", "01": "T", "10": "G", "11": "C"
}

class RansomwareClassifier:
    def __init__(self, model_paths: List[str], feature_csvs: List[str], ks: List[int]):
        # Initialize models and feature matrices
        self.models = [load(model_path) for model_path in model_paths]
        self.feature_matrices = [pd.read_csv(feature_csv) for feature_csv in feature_csvs]
        self.all_kmers = [matrix.columns[:-1] for matrix in self.feature_matrices]
        self.ks = ks
        self.entropy_threshold = 7.5

    def binary_to_dna(self, binary_data: str) -> str:
        return ''.join(BINARY_TO_DNA[binary_data[i:i+2]] for i in range(0, len(binary_data), 2))

    def extract_kmers(self, dna_sequence: str, k: int) -> List[str]:
        return [dna_sequence[i:i+k] for i in range(len(dna_sequence) - k + 1)]

    async def calculate_file_entropy(self, filepath: str) -> float:
        try:
            async with aiofiles.open(filepath, 'rb') as file:
                binary_data = await file.read()

            if not binary_data:
                return 0.0

            data_len = len(binary_data)
            byte_freq = {byte: binary_data.count(byte) for byte in set(binary_data)}
            entropy = -sum((freq / data_len) * math.log2(freq / data_len) for freq in byte_freq.values())
            return entropy
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            return -1.0
        except Exception as e:
            print(f"Error processing file {filepath}: {e}")
            return -1.0

    async def process_file(self, filepath: str, all_kmers: List[str], k: int) -> pd.DataFrame:
        try:
            async with aiofiles.open(filepath, 'rb') as file:
                binary_data = ''.join(f"{byte:08b}" for byte in await file.read())
            dna_sequence = self.binary_to_dna(binary_data)
            kmers = self.extract_kmers(dna_sequence, k)
            kmer_counts = Counter(kmers)
            features = {kmer: kmer_counts.get(kmer, 0) for kmer in all_kmers}
            return pd.DataFrame([features])
        except Exception as e:
            return None



    async def classify_file(self, filepath: str) -> str:
        # Get the file size and extension

        feature_vectors = await asyncio.gather(
            *[self.process_file(filepath, self.all_kmers[i], k) for i, k in enumerate(self.ks)]
        )
        if any(fv is None for fv in feature_vectors):
            return "Error processing file"

        entropy = await self.calculate_file_entropy(filepath)

        # Prediction logic
        prediction_mod1, prediction_mod2 = self.models[0].predict(feature_vectors[0])[0], self.models[1].predict(feature_vectors[1])[0]
        if prediction_mod1 == 1 and prediction_mod2 == 1:
            if entropy > self.entropy_threshold:
                print("[1100]")
                return "RANSOMWARE"

        prediction_mod3, prediction_mod4 = self.models[2].predict(feature_vectors[2])[0], self.models[3].predict(feature_vectors[3])[0]
        predictions = [prediction_mod1, prediction_mod2, prediction_mod3, prediction_mod4]

        if all(p == 0 for p in predictions):
            if entropy > 7.8:
                vt_result = await check_file(filepath)
                if "Error" not in vt_result:
                    if vt_result["inference"] == "Malicious":
                        return "RANSOMWARE"
            return "Benign"

        if prediction_mod1 == 1 and prediction_mod3 == 1 and prediction_mod4 == 1:
            return "RANSOMWARE"

        if prediction_mod1 == 1 and all(p == 0 for p in [prediction_mod2, prediction_mod3, prediction_mod4]):
            return "Benign"

        if prediction_mod1 == 0 and prediction_mod2 == 1 and prediction_mod3 == 1 and prediction_mod4 == 1:
            if entropy > self.entropy_threshold:
                return "RANSOMWARE"

        if prediction_mod1 == 0 and prediction_mod4 == 0 and prediction_mod2 == 1 and prediction_mod3 == 1:
            if entropy > 6.0:
                vt_result = await check_file(filepath)
                if "Error" not in vt_result:
                    if vt_result["inference"] == "Malicious":
                        return "RANSOMWARE"

        if prediction_mod1 == 0 and prediction_mod2 == 0 and prediction_mod3 == 1 and prediction_mod4 == 1:
            if entropy > self.entropy_threshold:
                vt_result = await check_file(filepath)
                if "Error" not in vt_result:
                    if vt_result["inference"] == "Malicious":
                        return "RANSOMWARE"

        if prediction_mod1 == 1 and prediction_mod2 == 0 and prediction_mod3 == 1 and prediction_mod4 == 0:
            if entropy > self.entropy_threshold:
                return "RANSOMWARE"

        if prediction_mod1 == 0 and prediction_mod2 == 1 and prediction_mod3 == 0 and prediction_mod4 == 1:
            if entropy > self.entropy_threshold:
                return "RANSOMWARE"

        if prediction_mod1 == 1 and prediction_mod2 == 0 and prediction_mod3 == 0 and prediction_mod4 == 1:
            if entropy > self.entropy_threshold:
                return "RANSOMWARE"

        if prediction_mod1 == 0 and prediction_mod2 == 1 and prediction_mod3 == 0 and prediction_mod4 == 0:
            if entropy > self.entropy_threshold:
                return "RANSOMWARE"

        if predictions.count(0) >= 3:
            return "Benign"
        if predictions.count(1) >= 3:
            return "RANSOMWARE"

        return "Benign"

async def scan_single_file(filepath: str) -> str:
    print("scanning...")
    
    # Check if file exists
    if not os.path.isfile(filepath):
        print(f"Error: File {filepath} does not exist.")
        return "Error: File does not exist"

    # Check file size
    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)  # Convert bytes to MB
    if file_size_mb > 20:  # Example threshold (100 MB)
        print(f"Error: File {filepath} exceeds size limit of 20 MB.")
        return "Error: File size exceeds limit"
    # Define paths to models and feature datasets
    model_paths = [
        './model/randomforest/ransomware_model4.joblib',
        './model/randomforest/ransomware_model5.joblib',
        './model/randomforest/ransomware_model6.joblib',
        './model/randomforest/ransomware_model7.joblib'
    ]
    feature_csvs = [
        './feature_datasets/ransomware_dna4.csv',
        './feature_datasets/ransomware_dna5.csv',
        './feature_datasets/ransomware_dna6.csv',
        './feature_datasets/ransomware_dna7.csv'
    ]
    ks = [4, 5, 6, 7]  # k-mer sizes

    # Instantiate the RansomwareClassifier
    classifier = RansomwareClassifier(
        model_paths=model_paths,
        feature_csvs=feature_csvs,
        ks=ks
    )

    # Scan the file
    result = await classifier.classify_file(filepath)
    print(result)
    return result

# # Example usage
# if __name__ == "__main__":
#     result = asyncio.run(scan_single_file("/home/rosn/Documents/PROJECTS/RANSOWARE/RBACK_v1/datasets/benign/Preview NFSU Aarti.pdf"))