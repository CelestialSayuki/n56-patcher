import os, sys, termios, select, time
SERIAL_PORT = "/dev/cu.usbserial-A600YUE4"
LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else 'vibration-serial.log'

out_f = open(LOG_FILE, "wb")
try:
    fd = os.open(SERIAL_PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    attrs[4] = termios.B115200; attrs[5] = termios.B115200
    attrs[0] = 0; attrs[1] = 0; attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL; attrs[3] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
except Exception as e:
    sys.exit(f"Failed to open serial: {e}")
try:
    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            chunk = os.read(fd, 4096)
            if chunk:
                out_f.write(chunk); out_f.flush()
except KeyboardInterrupt: pass
finally: os.close(fd); out_f.close()
