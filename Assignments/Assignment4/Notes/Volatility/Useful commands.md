## Send the exact content of the printf of a dump comamnd to a txt file. 
```bash
C:\volatility\vol.py --plugins=C:\volatility\plugins -f "Z:\Assessment 4\Evidence\victim_02.memory\victim_02.memory.raw" --profile=Win10x64_17134 dlldump -p 7956 --dump-dir "Z:\Assessment 4\Evidence\dumps" > "Z:\Assessment 4\Evidence\dumps\smartScreen-7956-list.txt"
``` 
