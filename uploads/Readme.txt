# Ransomware Detection and Mitigation Framework

## Overview
This framework is designed to detect and mitigate ransomware activities in real-time. It utilizes file entropy analysis, machine learning-based detection, and process monitoring to prevent ransomware from compromising the system.

## Key Features
1. **Real-Time Monitoring**:
   - Monitors specified directories for file changes (creation, modification).
   - Uses entropy analysis to detect potentially malicious files. and run scans on them

2. **Machine Learning Integration**:
   - Scans files using a machine learning model to identify ransomware.

3. **Validation before deleting**:
   - validates through online and local databases before attempting to delete

4. **Process Monitoring**:
   - Identifies processes consuming high CPU resources.
   - Suspends blacklisted processes or those exhibiting suspicious behavior.

5. **Network Protection**:
   - Disconnects the system from the network upon detecting ransomware to prevent further spread.


## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Prepare the directory structure:
   - Create a folder named `assets` and include the following files:
     - `disable_all_network.py`: Script to disable network connections.
     - `ransomware_dir_scanner.py`: Script for scanning directories.
     - `deep_scanner.py`: ML-based file scanner.

3. Update the `path_manager.py` file:
   - Add directories you want to monitor in the `paths` list.

4. Alternatively, integrate backup_files.py 
   - Specify paths list and a backup folder.
   
## Usage

Run the script:
```bash
python main.py
```

The framework will:
- Monitor directories for file changes.
- Analyze files for suspicious entropy.
- Use machine learning to scan files flagged as suspicious.
- Monitor system processes and suspend any matching the blacklist.

## How It Works

1. **File Monitoring**:
   - Uses the `watchdog` library to detect changes in monitored directories.

2. **Entropy Calculation**:
   - Computes the entropy of files to identify randomness associated with encryption activities.

3. **ML Scanning**:
   - Analyzes files using a trained machine learning model to classify ransomware.

4. **Process Suspension**:
   - Checks running processes against a predefined blacklist and suspends suspicious processes.

## Configuration

- **Entropy Threshold**: Default is set to `6.0`. Adjust in the `FileMonitor` class.
- **Change Threshold**: Maximum number of suspicious files before initiating a full scan (default: `5`).
- **Process Blacklist**: Modify the `_load_process_blacklist()` function in the `SystemMonitor` class to add/remove process keywords.

## Logs

All activities are logged in `application.log`, including:
- Detected file events.
- Entropy analysis results.
- Suspended processes.
- Deleted ransomware files.

## Limitations
- High entropy files may include legitimate encrypted data.
- Machine learning model accuracy depends on training quality.

## Future Enhancements
- Integrate real-time dashboards.
- Improve ML model accuracy.
- Add support for additional file analysis techniques.

## Contributors
- YASHASWINI
- VIDHI
- RHYTHM
- ROSHAN

---

**Note:** Use this framework responsibly. Ensure proper testing before deploying in critical environments.

