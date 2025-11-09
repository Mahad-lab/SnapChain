# SnapChain

## For verification

### Normal fast verify (uses cache + metadata)
python verify.py

### Force full re-hash of every file
python verify.py --full

### Custom log / base directory
python verify.py --log mylog.txt --dir /path/to/project

### Quiet mode (only summary)
python verify.py --quiet
