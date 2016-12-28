# minipwn

some scripts for exploitation

## Files

* minipwn.py: main library (usage: example.py)
* objdump.py: objdump with annotations
* patchgot.py: patch a GOT entry (e.g. alarm) to ret instruction
* gadgets.py: search the addresses of common ROP gadgets
* one-gadget-rce.sh: grep one-gadget-rce ROP gadget
* unstrip.py: try to find library symbols from static linked and stripped binaries (x86-64 only)
