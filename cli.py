import shlex
import serial, time
import subprocess
from pathlib import Path
import shutil
import configparser
import readline  # importing it gives input() arrow-key editing and up/down history

HISTORY_SIZE = 5
PIO_INI = Path(__file__).parent / "platformio.ini"

sketch_dir = None
arduino_serial = None
arduino_baudrate = None
arduino_port = None

def cmd_help(args):
    """/help - show this list"""
    names = {}  # group aliases (e.g. /message and /msg) under one function
    for name, fn in COMMANDS.items():
        names.setdefault(fn, []).append("/" + name)
    for fn, aliases in names.items():
        usage, _, desc = (fn.__doc__ or aliases[0]).partition(" - ")
        if len(aliases) > 1:
            desc += f" (also {', '.join(aliases[1:])})"
        print(f"  {usage:<30} {desc}")
    print(f"  {'/exit, /quit':<30} leave the shell")

def clear(args):
    print("\n" * (shutil.get_terminal_size().lines - 1), end="")

def set_port(args):
    """/set_port <port> - set the Arduino serial port"""
    global arduino_port
    arduino_port = args[0]
    
def set_baudrate(args):
    """/set_baudrate <rate> - set the baud rate for /serial_init"""
    global arduino_baudrate
    arduino_baudrate = args[0]
    
def set_sketch_dir(args):
    """/set_sketch_dir <dir> - set the sketch folder for /deploy"""
    global sketch_dir
    sketch_dir = Path(args[0]).expanduser().resolve()

def serial_init(args):
    """/serial_init [rate] - connect to the Arduino (rate defaults to /set_baudrate)"""
    global arduino_serial
    baud = args[0] if args else arduino_baudrate
    if arduino_port is None:
        print("error: arduino port is not specified (use /set_port)")
        return
    if baud is None:
        print("error: baud rate is not specified (pass one or use /set_baudrate)")
        return
    if not str(baud).isdigit():
        print(f"error: baud rate must be a number, got '{baud}'")
        return
    if isinstance(arduino_serial, serial.Serial) and arduino_serial.is_open:
        arduino_serial.close()
    arduino_serial = serial.Serial(arduino_port, int(baud), timeout=1)
    time.sleep(2)  # opening the port resets the Uno; wait for it to boot
    print(f"connected to {arduino_port} at {baud} baud")

def message(args):
    """/message <text> - send text to the Arduino and print its reply"""
    if not (isinstance(arduino_serial, serial.Serial) and arduino_serial.is_open):
        print("error: serial is not connected (use /serial_init)")
        return
    if not args:
        print("usage: /message <text>")
        return
    arduino_serial.write((" ".join(args) + "\n").encode())  # newline marks the end of the message
    reply = arduino_serial.readline().decode(errors="replace").strip()  # waits up to the 1 s serial timeout
    print(reply if reply else "(no response)")

def close_arduino(args):
    """/close - close the serial connection"""
    arduino_serial.close()

def debug_msg(args):
    """/debug - send 'ping' and print the reply"""
    arduino_serial.write(b'ping\n')
    print(arduino_serial.readline().decode().strip())

def deploy(args):
    """/deploy [port] [sketch_dir] - build and upload the sketch with PlatformIO"""
    # /deploy [port] [sketch_dir]; missing args fall back to /set_port and /set_sketch_dir
    port = args[0] if len(args) > 0 else arduino_port
    sketch = Path(args[1]).expanduser().resolve() if len(args) > 1 else sketch_dir

    if port is None:
        print("error: arduino port is not specified")
        return

    if sketch is None:
        print("error: sketch dir is not specified")
        return
    
    # the upload needs the serial port, so release it if this shell holds it
    if isinstance(arduino_serial, serial.Serial) and arduino_serial.is_open:
        arduino_serial.close()
        
    cmd = ["pio", "run", "-t", "upload", "-d", str(sketch.parent), "--upload-port", port]
    
    subprocess.run(cmd, check=True)

COMMANDS = {
    "help": cmd_help,
    "close": close_arduino,
    "debug": debug_msg,
    "deploy": deploy,
    "serial_init": serial_init,
    "message": message,
    "set_port": set_port,
    "set_baudrate": set_baudrate,
    "set_sketch_dir": set_sketch_dir,
    "msg": message
    # "clear": clear
}

def load_config():
    # defaults from platformio.ini: [platformio] src_dir, and upload_port from the first env that sets one
    global arduino_port, sketch_dir
    if not PIO_INI.exists():
        return
    ini = configparser.ConfigParser()
    ini.read(PIO_INI)
    sketch_dir = (PIO_INI.parent / ini.get("platformio", "src_dir", fallback="src")).resolve()
    for section in ini.sections():
        if section.startswith("env:") and ini.has_option(section, "upload_port"):
            arduino_port = ini.get(section, "upload_port")
            break

def main():
    load_config()
    print("arduino shell — type /help, /exit to quit")
    print(f"port: {arduino_port}, sketch dir: {sketch_dir}")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):   # Ctrl-D / Ctrl-C
            print()
            break
        while readline.get_current_history_length() > HISTORY_SIZE:
            readline.remove_history_item(0)  # keep only the last HISTORY_SIZE commands
        if not line:
            continue
        if line in ("/exit", "/quit"):
            break
        if line.startswith("/"):
            name, *args = shlex.split(line[1:])
            fn = COMMANDS.get(name)
            if fn is None:
                print(f"unknown command: /{name}")
                continue
            try:
                fn(args)
            except Exception as e:
                print(f"error: {e}")
        else:
            print(f"Not a valid command")
            continue

if __name__ == '__main__':
    main()