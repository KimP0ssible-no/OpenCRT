# OpenCRT's SecureCRT-style `crt` object for Python scripts (Python 3.8 or
# newer). OpenCRT starts Python with this file and the script to run (START);
# each crt call is one JSON line to OpenCRT, answered by one line back.
import builtins
import json
import os
import re
import sys
import threading
import traceback

# The channel to OpenCRT is on copies of stdin and stdout; the script's own
# go nowhere, so nothing it writes there can get mixed in.
_in = os.fdopen(os.dup(0), "r", encoding="utf-8")
_out = os.fdopen(os.dup(1), "w", encoding="utf-8")
_null = os.open(os.devnull, os.O_RDWR)
os.dup2(_null, 0)
os.dup2(_null, 1)
sys.stdin = open(os.devnull, encoding="utf-8")
_lock = threading.Lock()


class ScriptError(Exception):
    """A crt call that failed; crt.GetLastErrorMessage() has the text too."""


def _call(tab, name, *args):
    with _lock:
        _out.write(json.dumps({"tab": tab, "call": name, "args": list(args)}, default=str) + "\n")
        _out.flush()
        line = _in.readline()
    if not line:
        os._exit(1)  # OpenCRT stopped the script.
    reply = json.loads(line)
    if "error" in reply:
        raise ScriptError(reply["error"])
    return reply.get("ok")


def _prop(name, settable=False):
    def get(self):
        return _call(self._tab, name)

    def set(self, value):
        _call(self._tab, name, value)

    return property(get, set if settable else None)


def _texts(args):
    """WaitForStrings' arguments: a list (or several strings), then timeout and milliseconds."""
    texts, rest = [], []
    for arg in args:
        if isinstance(arg, (list, tuple)) and not rest:
            texts.extend(arg)
        elif isinstance(arg, str) and not rest:
            texts.append(arg)
        else:
            rest.append(arg)
    return [texts] + rest[:2]


class _Part(object):
    _tab = None

    def __init__(self, tab=None):
        self._tab = tab

    def __getattr__(self, name):
        raise AttributeError("OpenCRT's %s has no %s" % (type(self).__name__, name))


class Screen(_Part):
    def Send(self, text, *ignored):
        _call(self._tab, "Screen.Send", text)

    def WaitForString(self, text, timeout=0, milliseconds=False):
        return _call(self._tab, "Screen.WaitForString", text, timeout, milliseconds)

    def WaitForStrings(self, *args):
        return _call(self._tab, "Screen.WaitForStrings", *_texts(args))

    def ReadString(self, *args):
        return _call(self._tab, "Screen.ReadString", *_texts(args))

    def WaitForCursor(self, timeout=0, milliseconds=False):
        return _call(self._tab, "Screen.WaitForCursor", timeout, milliseconds)

    def Get(self, row1, col1, row2, col2):
        return _call(self._tab, "Screen.Get", row1, col1, row2, col2)

    def Get2(self, row1, col1, row2, col2):
        return _call(self._tab, "Screen.Get2", row1, col1, row2, col2)

    def Clear(self):
        _call(self._tab, "Screen.Clear")

    CurrentRow = _prop("Screen.CurrentRow")
    CurrentColumn = _prop("Screen.CurrentColumn")
    Rows = _prop("Screen.Rows")
    Columns = _prop("Screen.Columns")
    Selection = _prop("Screen.Selection")
    MatchIndex = _prop("Screen.MatchIndex")
    Synchronous = _prop("Screen.Synchronous", True)
    IgnoreCase = _prop("Screen.IgnoreCase", True)
    IgnoreEscape = _prop("Screen.IgnoreEscape", True)


class SessionConfiguration(_Part):
    def GetOption(self, name):
        return _call(None, "Config.GetOption", self._tab, name)

    def SetOption(self, name, value):
        _call(None, "Config.SetOption", self._tab, name, value)

    def Save(self, path=None):
        _call(None, "Config.Save", self._tab, path)


class Session(_Part):
    def Connect(self, spec="", wait=True, quiet=False):
        _call(self._tab, "Session.Connect", spec, wait, quiet)

    def ConnectInTab(self, spec="", wait=True, quiet=False):
        return Tab(_call(self._tab, "Session.ConnectInTab", spec, wait, quiet))

    def Disconnect(self):
        _call(self._tab, "Session.Disconnect")

    def SetStatusText(self, text):
        _call(self._tab, "Session.SetStatusText", text)

    Connected = _prop("Session.Connected")

    @property
    def Config(self):
        # Its handle stands where the tab does for the other objects.
        return SessionConfiguration(_call(self._tab, "Session.Config"))


class Tab(_Part):
    @property
    def Screen(self):
        return Screen(self._tab)

    @property
    def Session(self):
        return Session(self._tab)

    Caption = _prop("Tab.Caption")

    def Activate(self):
        _call(self._tab, "Tab.Activate")


class Dialog(_Part):
    def MessageBox(self, message, title="", buttons=0):
        return _call(None, "Dialog.MessageBox", message, title, buttons)

    def Prompt(self, message, title="", default="", isPassword=False):
        return _call(None, "Dialog.Prompt", message, title, default, isPassword)

    def FileOpenDialog(self, title="", buttonLabel="", defaultFilename="", filter=""):
        return _call(None, "Dialog.FileOpenDialog", title, buttonLabel, defaultFilename, filter)

    def FileSaveDialog(self, title="", defaultFilename="", filter=""):
        return _call(None, "Dialog.FileSaveDialog", title, defaultFilename, filter)


class Clipboard(_Part):
    Format = "CF_TEXT"
    Text = _prop("Clipboard.Text", True)


class Window(_Part):
    Caption = _prop("Window.Caption")


class FileTransfer(_Part):
    DownloadFolder = _prop("FileTransfer.DownloadFolder")
    ZmodemUploadAscii = _prop("FileTransfer.ZmodemUploadAscii", True)

    def AddToUploadList(self, path):
        _call(None, "FileTransfer.AddToUploadList", path)

    def ClearUploadList(self):
        _call(None, "FileTransfer.ClearUploadList")

    def SendXmodem(self, path):
        _call(None, "FileTransfer.SendXmodem", path)

    def SendYmodem(self):
        _call(None, "FileTransfer.SendYmodem")

    def SendKermit(self):
        _call(None, "FileTransfer.SendKermit")

    def ReceiveXmodem(self, name):
        _call(None, "FileTransfer.ReceiveXmodem", name)

    def ReceiveYmodem(self):
        _call(None, "FileTransfer.ReceiveYmodem")

    def ReceiveKermit(self):
        _call(None, "FileTransfer.ReceiveKermit")


class Arguments(_Part):
    def __init__(self, args):
        self._args = list(args)

    @property
    def Count(self):
        return len(self._args)

    def GetArg(self, index):
        return self._args[index]

    __getitem__ = GetArg

    def __len__(self):
        return len(self._args)

    def __iter__(self):
        return iter(self._args)


class Crt(_Part):
    def __init__(self, args):
        self.Screen = Screen()
        self.Session = Session()
        self.Dialog = Dialog()
        self.Clipboard = Clipboard()
        self.Window = Window()
        self.FileTransfer = FileTransfer()
        self.Arguments = Arguments(args)

    ScriptFullName = _prop("crt.ScriptFullName")
    Version = _prop("crt.Version")

    def Sleep(self, milliseconds):
        _call(None, "crt.Sleep", milliseconds)

    def GetScriptTab(self):
        return Tab(None)

    def GetActiveTab(self):
        return Tab(_call(None, "crt.GetActiveTab"))

    def GetTab(self, number):
        return Tab(_call(None, "crt.GetTab", number))

    def GetTabCount(self):
        return _call(None, "crt.GetTabCount")

    def GetLastError(self):
        return _call(None, "crt.GetLastError")

    def GetLastErrorMessage(self):
        return _call(None, "crt.GetLastErrorMessage")

    def ClearLastError(self):
        _call(None, "crt.ClearLastError")

    def OpenSessionConfiguration(self, path="Default"):
        return SessionConfiguration(_call(None, "crt.OpenSessionConfiguration", path))

    def Quit(self):
        _call(None, "crt.Quit")


class _Status(object):
    """print() goes to the tab's status bar, a line at a time."""

    encoding = "utf-8"

    def __init__(self):
        self._line = ""

    def write(self, text):
        lines = (self._line + text).split("\n")
        self._line = lines.pop()
        for line in lines:
            if line.strip():
                _call(None, "Session.SetStatusText", line.rstrip("\r"))
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False


CONSTANTS = dict(
    BUTTON_OK=0, BUTTON_CANCEL=1, BUTTON_ABORTRETRYIGNORE=2, BUTTON_YESNOCANCEL=3, BUTTON_YESNO=4, BUTTON_RETRYCANCEL=5,
    ICON_STOP=16, ICON_QUESTION=32, ICON_WARN=48, ICON_INFO=64, DEFBUTTON1=0, DEFBUTTON2=256, DEFBUTTON3=512,
    IDOK=1, IDCANCEL=2, IDABORT=3, IDRETRY=4, IDIGNORE=5, IDYES=6, IDNO=7,
)


# Audit events a locked script needs the user's leave for (see _lock_down).
_PROGRAMS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile", "os.fork", "os.forkpty", "pty.spawn")
_NETWORK = ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg")
_CHANGES = ("os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.chmod", "os.chown", "os.utime", "os.truncate", "os.symlink", "os.link",
            "shutil.rmtree", "shutil.copyfile", "shutil.copytree", "shutil.move")
_SYSTEM = {"ctypes.": "load native code (ctypes)", "winreg.": "use the Windows registry", "resource.setrlimit": "change its limits",
           "resource.prlimit": "change its limits", "gc.get_": "look through Python's memory"}


def _lock_down(folders):
    """Ask OpenCRT (which asks the user) before the script uses files outside
    `folders` (reading Python's own is fine), runs programs, uses the network
    or reaches into the system; once allowed, it runs unlocked."""
    # Kept in this closure, out of the script's reach: crt.py's globals are not.
    ask, real, full, devnull, write_flags = _call, os.path.realpath, os.path.abspath, os.devnull, os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    programs, network, changes, system = _PROGRAMS, _NETWORK, _CHANGES, dict(_SYSTEM)
    norm = lambda p: os.path.normcase(real(p))
    writable = [norm(f) for f in folders]
    python = set([sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix] + [p for p in sys.path if p])
    readable = writable + [norm(p) for p in python]
    locked = [True]
    limit = None
    if sys.platform.startswith("linux"):
        # Not macOS: its system libraries alone take more address space than this.
        import resource
        try:
            limit = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (2 << 30, limit[1]))
        except (ValueError, OSError):
            limit = None

    def inside(path, roots):
        if isinstance(path, int):
            return True  # an open file
        try:
            path = os.fsdecode(path if path is not None else ".")
            if path == devnull:
                return True
            path = norm(path)
        except (TypeError, ValueError, OSError):
            return False
        return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)

    def wants(what):
        ask(None, "Trust", what[:300])  # OpenCRT ends the script if the user says no.
        locked[0] = False
        if limit:
            resource.setrlimit(resource.RLIMIT_AS, limit)

    def hook(event, args):
        if not locked[0]:
            return
        if event == "open":
            path, mode, flags = args
            write = any(c in mode for c in "wax+") if isinstance(mode, str) else bool(flags & write_flags)
            if not inside(path, writable if write else readable):
                wants("%s %s" % ("write to" if write else "read", full(os.fsdecode(path))))
        elif event in ("os.listdir", "os.scandir"):
            if not inside(args[0], readable):
                wants("list the folder %s" % full(os.fsdecode(args[0] or ".")))
        elif event in changes:
            for path in args[:2]:
                if isinstance(path, (str, bytes, os.PathLike)) and not inside(path, writable):
                    return wants("change %s" % full(os.fsdecode(path)))
        elif event in ("os.kill", "os.killpg"):
            wants("signal another program (process %s)" % (args[0],))
        elif event in programs:
            wants("run a program: %s" % (args[1] if event == "subprocess.Popen" else args[0] if args else event))
        elif event in network:
            wants("use the network (%s)" % (args[1],))
        else:
            for prefix, what in system.items():
                if event.startswith(prefix):
                    return wants(what)

    sys.addaudithook(hook)


def _run():
    if sys.version_info < (3, 8):
        sys.exit("OpenCRT runs Python scripts with Python 3.8 or newer; this is Python %s. Install a newer one and choose it in Global Options > General."
                 % sys.version.split()[0])
    path, args = START["script"], START["args"]
    with open(path, "rb") as f:
        source = f.read()
    try:
        code = compile(source, path, "exec")
    except SyntaxError as e:
        head = source[:400].decode("utf-8", "replace")
        if re.search(r'\$language\s*=\s*"python"', head, re.I) or "Missing parentheses" in str(e):
            sys.exit("This is a Python 2 script; OpenCRT runs Python 3 scripts. Convert it (for example with 2to3) and run it again.")
        raise
    crt = Crt(args)
    # Modules the script imports see crt and the MessageBox constants too.
    builtins.crt = crt
    for name, value in CONSTANTS.items():
        setattr(builtins, name, value)
    for cls in (Crt, Dialog):
        for name, value in CONSTANTS.items():
            setattr(cls, name, value)
    sys.argv = [path] + list(args)
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))
    sys.stdout = _Status()
    if START["locked"]:
        _lock_down(START["folders"])
    try:
        exec(code, {"__name__": "__main__", "__file__": path, "__builtins__": builtins, "crt": crt})
    except Exception as e:
        frames = [f for f in traceback.extract_tb(sys.exc_info()[2]) if f.filename != "<opencrt>"]
        mine = [f for f in frames if f.filename == path]
        where = " (line %d)" % mine[-1].lineno if mine else ""
        sys.stderr.write("%s: %s%s\n%s" % (type(e).__name__, e, where, "".join(traceback.format_list(frames))))
        sys.exit(1)


_run()
