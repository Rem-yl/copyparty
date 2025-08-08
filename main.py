#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals
import re
import os
import sys
import time
import shutil
import signal
import tarfile
import hashlib
import platform
import tempfile
import traceback
import subprocess as sp


"""
to edit this file, use HxD or "vim -b"
  (there is compressed stuff at the end)

run me with python 2.7 or 3.3+ to unpack and run copyparty

there's zero binaries! just plaintext python scripts all the way down
  so you can easily unpack the archive and inspect it for shady stuff

the archive data is attached after the b"\n# eof\n" archive marker,
  b"?0" decodes to b"\x00"
  b"?n" decodes to b"\n"
  b"?r" decodes to b"\r"
  b"??" decodes to b"?"
"""


# set by make-sfx.sh
VER = "1.19.0"
SIZE = 910018
CKSUM = "0d0c013b09bb942617778735"
STAMP = 1754605098

PY2 = sys.version_info < (3,)
PY37 = sys.version_info > (3, 7)
WINDOWS = sys.platform in ["win32", "msys"]
sys.dont_write_bytecode = True
me = os.path.abspath(os.path.realpath(__file__))


def eprint(*a, **ka):
    ka["file"] = sys.stderr
    print(*a, **ka)


def msg(*a, **ka):
    if a:
        a = ["[SFX]", a[0]] + list(a[1:])

    eprint(*a, **ka)


def u8(gen):
    try:
        for s in gen:
            yield s.decode("utf-8", "ignore")
    except:
        yield s
        for s in gen:
            yield s


def yieldfile(fn):
    s = 64 * 1024
    with open(fn, "rb", s * 4) as f:
        for block in iter(lambda: f.read(s), b""):
            yield block


def hashfile(fn):
    h = hashlib.sha1()
    for block in yieldfile(fn):
        h.update(block)

    return h.hexdigest()[:24]


def unpack():
    """unpacks the tar yielded by `data`"""
    name = "pe-copyparty"
    try:
        name += "." + str(os.geteuid())
    except:
        pass

    tag = "v" + str(STAMP)
    top = tempfile.gettempdir()
    opj = os.path.join
    ofe = os.path.exists
    final = opj(top, name)
    san = opj(final, "copyparty/up2k.py")
    for suf in range(0, 9001):
        withpid = "%s.%d.%s" % (name, os.getpid(), suf)
        mine = opj(top, withpid)
        if not ofe(mine):
            break

    tar = opj(mine, "tar")

    try:
        if tag in os.listdir(final) and ofe(san):
            msg("found early")
            return final
    except:
        pass

    sz = 0
    os.mkdir(mine)
    with open(tar, "wb") as f:
        for buf in get_payload():
            sz += len(buf)
            f.write(buf)

    ck = hashfile(tar)
    if ck != CKSUM:
        t = "\n\nexpected %s (%d byte)\nobtained %s (%d byte)\nsfx corrupt"
        raise Exception(t % (CKSUM, SIZE, ck, sz))

    with tarfile.open(tar, "r:gz") as tf:
        # this is safe against traversal
        try:
            tf.extractall(mine, filter="tar")
        except TypeError:
            tf.extractall(mine)

    os.remove(tar)

    with open(opj(mine, tag), "wb") as f:
        f.write(b"h\n")

    try:
        if tag in os.listdir(final) and ofe(san):
            msg("found late")
            return final
    except:
        pass

    try:
        if os.path.islink(final):
            os.remove(final)
        else:
            shutil.rmtree(final)
    except:
        pass

    for fn in u8(os.listdir(top)):
        if fn.startswith(name) and fn != withpid:
            try:
                old = opj(top, fn)
                if time.time() - os.path.getmtime(old) > 86400:
                    shutil.rmtree(old)
            except:
                pass

    try:
        os.symlink(mine, final)
    except:
        try:
            os.rename(mine, final)
            return final
        except:
            msg("reloc fail,", mine)

    return mine


def get_payload():
    """yields the binary data attached to script"""
    with open(me, "rb") as f:
        buf = f.read().rstrip(b"\r\n")

    ptn = b"\n# eof\n#"
    a = buf.find(ptn)
    if a < 0:
        raise Exception("could not find archive marker")

    esc = {b"??": b"?", b"?r": b"\r", b"?n": b"\n", b"?0": b"\x00"}
    buf = buf[a + len(ptn):].replace(b"\n#", b"")
    p = 0
    while buf:
        a = buf.find(b"?", p)
        if a < 0:
            yield buf[p:]
            break
        elif a == p:
            yield esc[buf[p: p + 2]]
            p += 2
        else:
            yield buf[p:a]
            p = a


def confirm(rv):
    msg()
    msg("retcode", rv if rv else traceback.format_exc())
    if WINDOWS:
        msg("*** hit enter to exit ***")
        try:
            raw_input() if PY2 else input()
        except:
            pass

    sys.exit(rv or 1)


def run(tmp, j2, ftp):
    msg("jinja2:", j2 or "bundled")
    msg("pyftpd:", ftp or "bundled")
    msg("sfxdir:", tmp)
    msg()

    sys.argv.append("--sfx-tpoke=" + tmp)

    ld = (("", ""), (j2, "j2"), (ftp, "ftp"), (not PY2, "py2"), (PY37, "py37"))
    ld = [os.path.join(tmp, b) for a, b in ld if not a]

    if any([re.match(r"^-.*j[0-9]", x) for x in sys.argv]):
        run_s(ld)
    else:
        run_i(ld)


def run_i(ld):
    for x in ld:
        sys.path.insert(0, x)

    e = os.environ
    e["PRTY_NO_IMPRESO"] = "1"

    from copyparty.__main__ import main as p

    p()


def run_s(ld):
    c = "import sys,runpy;" + "".join(['sys.path.insert(0,r"' + x.replace("\\", "/") +
                                      '");' for x in ld]) + 'runpy.run_module("copyparty",run_name="__main__")'
    c = [str(x) for x in [sys.executable, "-c", c] + list(sys.argv[1:])]
    msg("\n", c, "\n")
    p = sp.Popen(c)

    def bye(*a):
        p.send_signal(signal.SIGINT)

    signal.signal(signal.SIGTERM, bye)
    p.wait()

    raise SystemExit(p.returncode)


def main():
    sysver = str(sys.version).replace("\n", "\n" + " " * 18)
    pktime = time.strftime("%Y-%m-%d, %H:%M:%S", time.gmtime(STAMP))
    msg()
    msg("   this is: copyparty", VER)
    msg(" packed at:", pktime, "UTC,", STAMP)
    msg("archive is:", me)
    msg("python bin:", sys.executable)
    msg("python ver:", platform.python_implementation(), sysver)
    msg()

    arg = ""
    try:
        arg = sys.argv[1]
    except:
        pass

    tmp = os.path.realpath(unpack())

    try:
        from jinja2 import __version__ as j2
    except:
        j2 = None

    try:
        from pyftpdlib.__init__ import __ver__ as ftp
    except:
        ftp = None

    try:
        run(tmp, j2, ftp)
    except SystemExit as ex:
        c = ex.code
        if c not in [0, -15]:
            confirm(ex.code)
    except KeyboardInterrupt:
        pass
    except:
        confirm(0)


if __name__ == "__main__":
    main()
