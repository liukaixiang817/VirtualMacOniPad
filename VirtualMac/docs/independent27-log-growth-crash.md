# Owned log growth must not stop the guest

Normal242 ran App213 / Runtime150 through approximately eight hours at the
login screen. On login, a new GPU task was refused with EACCES (13), followed
by a PGFifoThread null-mutex crash. The actual failed session log was 3,592,362
bytes. All GPU runtime file hashes, ownership and private directory modes still
matched the installed product.

`OwnedLogDescriptorsV6` rejected any otherwise valid own log larger than
2,097,152 bytes before `posix_spawn`. Log growth therefore became an unintended
GPU availability condition. Normal243, using the same installed input and
runtime bytes with a fresh smaller log, logged in and rendered Safari normally.
This separates the observed failure from merely adding the native trackpad.

Consumer7 removes only that upper-size test. It still verifies the canonical
pathname, regular file, uid/gid 501, mode0600, one link, matching FD path/device/
inode, writable append status, and the same checks immediately before spawn.
It reads metadata only, so log size does not allocate or copy the file contents.
Child-only standard descriptor inheritance and all code/endpoint checks remain.
No iPadOS identity or permission change is involved.

The macOS host regression extracts the actual V6 and V7 guard functions. V6
rejects a valid 2 MiB+1 log; V7 accepts it and 16 MiB. Wrong mode, a descriptor
without append status and an extra hard link remain rejected. Only fixture
path and host ownership are adapted; production remains501:501.

Runtime151 / App214 passed the targeted actual Normal244 regression on
2026-10-21 UTC. With the guest still at login, the same canonical own log was
backed up and extended using clearly labelled finite test payload from 228,037
to 2,984,153 bytes. This is a size fixture, not invented guest events. The
unchanged live App29182 / VMM29207 then logged in and displayed the actual
wallpaper, menu bar and Dock at the 16-second native capture. New genuine GPU
tasks (including PIDs29847 onward) started after the size fixture. At the
subsequent native read, the log was3,322,949 bytes and the same VMM remained
running. Safari also rendered its local scrolling test page.

CPU91, native GPU processing, Bluetooth audio isolation and input objects are
unchanged. This accepts the specific log-size failure regression, not long-run
stability or Safari performance. Diagnostic log rotation remains a separate
follow-up; log length must not become a GPU authorization condition again.
