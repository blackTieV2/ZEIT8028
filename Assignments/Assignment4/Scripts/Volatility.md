## List of Volatility 2 commands

### Command to run strings over a module. Here we are searching for only scvhost in the `pslist` module
```powershell
C:\volatility\vol.py -f "Z:\Assessment 4\Evidence\victim_02.memory\victim_02.memory.raw" --profile=Win10x64_17134 psscan | Select-String svchost > "Z:\Assessment 4\Evidence\Volalilty\pslist-String-svchost-Vic2.txt"
```

### cmd to dump out a PID - `procdump` 
```powershell
C:\volatility\vol.py -f "Z:\Assessment 4\Evidence\victim_01.memory\victim_01.memory.raw" --profile=Win10x64_17134 procdump -p 996 --dump-dir="C:\Users\Flare\Documents\Autopsy\8028\Export"
```

### Yara Rules
```powershell
python C:\volatility\vol.py -f C:\Users\Flare\Documents\Autopsy\A4\Evidence\victim_02.memory.raw --profile=Win10x64_17134 yarascan -y C:\volatility\volatility\yourrule.yar
```

