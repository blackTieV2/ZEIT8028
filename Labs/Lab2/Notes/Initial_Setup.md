# Initial Setup

## Unzip Disk Image

- **Command Used**: `7z x "Lab 2 - Disk Forensics.7z"`
- **Result**: Successfully extracted `disk.bin`

## Verify Disk Image Integrity

- **Command Used**: `sha1sum disk.bin`
- **Expected SHA1**: `ba7dc57e08bb6e3393aee15c713ae04feadcd181`
- **Result**: `ba7dc57e08bb6e3393aee15c713ae04feadcd181` (Match)

- **Command Used**: `md5sum disk.bin`
- **Expected MD5**: `78a52b5bac78f4e711607707ac0e3f93`
- **Result**: `78a52b5bac78f4e711607707ac0e3f93` (Match)
![Initial Setup Screenshot]()

