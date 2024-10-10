## List of Vol.py comamnds

### Command to run strings over a module. Here we are searching for only scvhost in the `pslist` module
```powershell
C:\volatility\vol.py -f "Z:\Assessment 4\Evidence\victim_02.memory\victim_02.memory.raw" --profile=Win10x64_17134 psscan | Select-String svchost > "Z:\Assessment 4\Evidence\Volalilty\pslist-String-svchost-Vic2.txt"
```
