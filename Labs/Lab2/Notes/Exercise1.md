### Documentation of Findings

#### Step 1: Disk Layout Analysis
- **Command**: `mmls disk.bin`
- **Output**:
  ```
  DOS Partition Table
  Offset Sector: 0
  Units are in 512-byte sectors

        Slot      Start        End          Length       Description
  000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
  001:  -------   0000000000   0000000062   0000000063   Unallocated
  002:  000:000   0000000063   0020948759   0020948697   NTFS / exFAT (0x07)
  003:  -------   0020948760   0020971519   0000022760   Unallocated
  ```

#### Step 2: Filesystem Verification
- **Command**: `hexdump -C -s 32256 -n 512 disk.bin`
- **Output**:
  ```
  00007e00  eb 52 90 4e 54 46 53 20  20 20 20 00 02 08 00 00  |.R.NTFS    .....|
  00007e10  00 00 00 00 00 f8 00 00  3f 00 ff 00 3f 00 00 00  |........?...?...|
  00007e20  00 00 00 00 80 00 80 00  d8 a6 3f 01 00 00 00 00  |..........?.....|
  00007e30  00 00 0c 00 00 00 00 00  6d fa 13 00 00 00 00 00  |........m.......|
  00007e40  f6 00 00 00 01 00 00 00  1f c2 4f 74 08 50 74 7e  |..........Ot.Pt~|
  00007e50  00 00 00 00 fa 33 c0 8e  d0 bc 00 7c fb b8 c0 07  |.....3.....|....|
  00007e60  8e d8 e8 16 00 b8 00 0d  8e c0 33 db c6 06 0e 00  |..........3.....|
  00007e70  10 e8 53 00 68 00 0d 68  6a 02 cb 8a 16 24 00 b4  |..S.h..hj....$..|
  00007e80  08 cd 13 73 05 b9 ff ff  8a f1 66 0f b6 c6 40 66  |...s......f...@f|
  00007e90  0f b6 d1 80 e2 3f f7 e2  86 cd c0 ed 06 41 66 0f  |.....?.......Af.|
  00007ea0  b7 c9 66 f7 e1 66 a3 20  00 c3 b4 41 bb aa 55 8a  |..f..f. ...A..U.|
  00007eb0  16 24 00 cd 13 72 0f 81  fb 55 aa 75 09 f6 c1 01  |.$...r...U.u....|
  00007ec0  74 04 fe 06 14 00 c3 66  60 1e 06 66 a1 10 00 66  |t......f`..f...f|
  00007ed0  03 06 1c 00 66 3b 06 20  00 0f 82 3a 00 1e 66 6a  |....f;. ...:..fj|
  00007ee0  00 66 50 06 53 66 68 10  00 01 00 80 3e 14 00 00  |.fP.Sfh.....>...|
  00007ef0  0f 85 0c 00 e8 b3 ff 80  3e 14 00 00 0f 84 61 00  |........>.....a.|
  00007f00  b4 42 8a 16 24 00 16 1f  8b f4 cd 13 66 58 5b 07  |.B..$.......fX[.|
  00007f10  66 58 66 58 1f eb 2d 66  33 d2 66 0f b7 0e 18 00  |fXfX..-f3.f.....|
  00007f20  66 f7 f1 fe c2 8a ca 66  8b d0 66 c1 ea 10 f7 36  |f......f..f....6|
  00007f30  1a 00 86 d6 8a 16 24 00  8a e8 c0 e4 06 0a cc b8  |......$.........|
  00007f40  01 02 cd 13 0f 82 19 00  8c c0 05 20 00 8e c0 66  |........... ...f|
  00007f50  ff 06 10 00 ff 0e 0e 00  0f 85 6f ff 07 1f 66 61  |..........o...fa|
  00007f60  c3 a0 f8 01 e8 09 00 a0  fb 01 e8 03 00 fb eb fe  |................|
  00007f70  b4 01 8b f0 ac 3c 00 74  09 b4 0e bb 07 00 cd 10  |.....<.t........|
  00007f80  eb f2 c3 0d 0a 41 20 64  69 73 6b 20 72 65 61 64  |.....A disk read|
  00007f90  20 65 72 72 6f 72 20 6f  63 63 75 72 72 65 64 00  | error occurred.|
  00007fa0  0d 0a 4e 54 4c 44 52 20  69 73 20 6d 69 73 73 69  |..NTLDR is missi|
  00007fb0  6e 67 00 0d 0a 4e 54 4c  44 52 20 69 73 20 63 6f  |ng...NTLDR is co|
  00007fc0  6d 70 72 65 73 73 65 64  00 0d 0a 50 72 65 73 73  |mpressed...Press|
  00007fd0  20 43 74 72 6c 2b 41 6c  74 2b 44 65 6c 20 74 6f  | Ctrl+Alt+Del to|
  00007fe0  20 72 65 73 74 61 72 74  0d 0a 00 00 00 00 00 00  | restart........|
  00007ff0  00 00 00 00 00 00 00 00  83 a0 b3 c9 00 00 55 aa  |..............U.|
  00008000
  ```
- **Verification**: The filesystem is identified as NTFS.
 ![Verification Screenshot](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/ScreenShots/Lab2-HexDump-SC2.JPG)

#### Step 3: Filesystem Extraction
- **Command**: `dd if=disk.bin of=ntfs_partition.bin bs=512 skip=63 count=20948697`
- **Output**: 
  ```
  20948697+0 records in
  20948697+0 records out
  10725732864 bytes (11 GB, 10 GiB) copied, 59.566 s, 180 MB/s
  ```

- **SHA1 Hash Calculation**: `sha1sum ntfs_partition.bin`
- **Output**: 
  ```
  f8ec0f28b54ef1a9d4f3775c1903bc28493a2743  ntfs_partition.bin
  ```

- **Findings**:
  - Successfully extracted the NTFS filesystem from the disk image.
  - SHA1 hash of the extracted filesystem: `f8ec0f28b54ef1a9d4f3775c1903bc28493a2743`
