### Exercise 2: Initial Inspection

#### a) Dynamically Inspect the Filesystem

**Mounting the Filesystem:**

```bash
sudo mount -o ro,loop /mnt/8028HDD/Module\ 2/Lab\ 2/Lab2Image/Lab\ 2\ -\ Disk\ Forensics/lab2_partition.bin /mnt/8028HDD/Module\ 2/Lab\ 2/mnt/lab2_partition
```

**Verifying the Mount:**

```bash
ls /mnt/8028HDD/Module\ 2/Lab\ 2/mnt/lab2_partition
```
 ![Verify Mount Screenshot](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/ScreenShots/Lab2-Ex2-MountFS-SC4.JPG)
This confirms the filesystem is mounted and the contents are accessible.

#### b) Statically Inspect the Filesystem
[More information about the Sleuth Kit fls  - See Manual](https://www.sleuthkit.org/sleuthkit/man/fls.html)

**Listing Filesystem Contents:**

```bash
fls lab2_partition.bin
```
 ![StaticInspection Screenshot](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/ScreenShots/Lab2-Ex2-ListImage-SC5.JPG)
 
### Benefits and Pitfalls of Inspection Methods

**Dynamic Inspection:**

**Benefits:**
1. **User-Friendly:** Easy to navigate and explore the filesystem using familiar file browsing tools.
2. **Real-Time Interaction:** Allows for real-time access and manipulation of the filesystem as if it were part of the local filesystem.

**Pitfalls:**
1. **Risk of Modification:** Mounting in read-only mode mitigates this, but there's always a risk of accidental modification.
2. **Potential for Missing Hidden Files:** Some forensic artifacts may not be immediately visible or accessible.

**Static Inspection:**

**Benefits:**
1. **Forensic Integrity:** No risk of modifying the evidence as it's read directly from the image.
2. **Comprehensive:** Tools like `fls` can reveal hidden and deleted files that are not easily accessible through dynamic inspection.

**Pitfalls:**
1. **Complexity:** Requires familiarity with command-line tools and interpreting their output.
2. **Time-Consuming:** Can be more time-consuming to manually parse and analyze the results.

### Risks Posed to Evidence

**Dynamic Inspection Risks:**
- **Modification Risk:** Although minimal in read-only mode, there's always a slight risk of accidental writes or alterations.
- **Artifact Exposure:** Dynamic mounts may not expose all forensic artifacts, potentially missing crucial evidence.

**Static Inspection Risks:**
- **Interpretation Errors:** Misinterpretation of raw data outputs can lead to incorrect conclusions.
- **Overlooked Artifacts:** Static tools might miss some artifacts that dynamic tools could easily reveal through direct interaction.

### Next Steps

1. **Document Everything:** Keep detailed notes of every command and result.
2. **Analyze Specific Directories and Files:** Focus on the directories and files that are likely to contain relevant information, such as `Documents and Settings`, `Program Files`, and `WINDOWS`.
3. **Search for Relevant Artifacts:** Look for files or metadata that can provide answers to the key questions:
   - When was the spreadsheet created?
   - How did it get from Jean's computer to the competitor's website?
   - Who else was involved?
