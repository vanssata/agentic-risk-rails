# Research: journal (W1-B)

## FACTS
claim | URL | [V]/[U]
--- | --- | ---
With O_APPEND the offset adjustment and the write are one atomic step; before Linux 3.14 processes sharing an open file description could race and overlap output (fixed in 3.14) | https://man7.org/linux/man-pages/man2/write.2.html | [V]
write(2) page says nothing about PIPE_BUF; PIPE_BUF atomicity is a pipe/FIFO guarantee, not a regular-file one. Atomicity of large appends to regular files is therefore not promised there, so we serialize writers with flock | https://man7.org/linux/man-pages/man2/write.2.html | [V] (absence); [U] for macOS behaviour
flock locks belong to the open file description; separate open() calls conflict even in one process; fork/dup share; locks survive execve; advisory only | https://man7.org/linux/man-pages/man2/flock.2.html | [V]
Lock released on LOCK_UN or when all descriptors of the description are closed | https://man7.org/linux/man-pages/man2/flock.2.html | [V]
NFS: flock local-only up to 2.6.11; from 2.6.12 emulated with fcntl byte-range locks (exclusive needs write-open); 2.6.37 added local_lock option | https://man7.org/linux/man-pages/man2/flock.2.html | [V]
fsync flushes data+metadata and blocks until the device reports completion; fdatasync skips non-essential metadata (size changes still flushed) | https://man7.org/linux/man-pages/man2/fsync.2.html | [V]
fsync of a file does not guarantee its directory entry is durable; fsync on the directory fd is needed | https://man7.org/linux/man-pages/man2/fsync.2.html | [V]
macOS fsync does not force the drive cache; F_FULLFSYNC is needed for that | (not fetched) | [U]
AI-DLC (awslabs/aidlc-workflows) keeps an audit event taxonomy in aidlc-shared/audit-format.md; a third-party summary says 91 event types in 22 categories, a Japanese article says 82 (DES cites 131: counts differ by version); append-only, written via appendAuditEntry with locked/unlocked variants | https://deepwiki.com/awslabs/aidlc-workflows/6.2-audit-and-logging-tools | [U] (third-party summary)

## READ
man7 write(2), flock(2), fsync(2); DeepWiki page via search snippet.

## DECISIONS
- One exclusive flock on `<root>/.rr/.lock` serializes Append and Close (and the TASK_IN_FLIGHT check), since the task file is renamed by Close and the in-flight check spans files. Local filesystems only; NFS out of scope.
- Writes use O_APPEND plus fsync(file); the directory is fsynced after create/rename.
- prev_sha256 = hex sha256 of the previous line's exact bytes without the newline; first line: sha256 of the empty string.
- Verify reports the line whose prev_sha256 does not match, i.e. editing line N is reported at line N+1.

## GAPS
- macOS F_FULLFSYNC not used/verified. Tampering with the LAST line is not detectable by the chain alone (needs an external anchor at close/runner).
- AI-DLC repo itself not read; event count unverified.

## COST
Three man-page fetches and one search.
