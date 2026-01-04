from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = 'ctf_secret_key_2024'

# Simulated users
users = {
    'admin': 'admin123',
    'multip': 'multip123',
    'achu': 'password@123'
}

# Shadow hash for achu: password123

FLAG = "CTF{Web_LFI_Sudo_Cat_Password_Crack}"

# Simulated file system
filesystem = {
    '/': {
        'type': 'dir',
        'contents': ['home', 'etc', 'usr', 'bin', 'var'],
        'permissions': 'drwxr-xr-x'
    },
    '/home': {
        'type': 'dir',
        'contents': ['achu', 'admin', 'multip'],
        'permissions': 'drwxr-xr-x'
    },
    '/home/achu': {
        'type': 'dir',
        'contents': ['shell.txt', 'flag.png', '.bashrc'],
        'permissions': 'drwxr-x---'
    },
    '/home/admin': {
        'type': 'dir',
        'contents': ['readme.txt'],
        'permissions': 'drwxr-x---'
    },
    '/home/multip': {
        'type': 'dir',
        'contents': ['notes.txt'],
        'permissions': 'drwxr-x---'
    },
    '/etc': {
        'type': 'dir',
        'contents': ['passwd', 'shadow', 'group'],
        'permissions': 'drwxr-xr-x'
    }
}

# Store current directory per session
def get_current_dir():
    return session.get('current_dir', '/home/achu')

def set_current_dir(path):
    session['current_dir'] = path

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = request.args.get('error', '')

    if error:
        error_path = error.replace('/var/www/html/ctf/', '')

        if error_path.startswith('../../../../'):
            clean_path = error_path.replace('../../../../', '')

            if 'etc/passwd' in clean_path:
                return render_template('login.html',
                    file_content="""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
achu:x:1000:1000::/home/achu:/bin/bash
admin:x:1001:1001::/home/admin:/bin/bash
multip:x:1002:1002::/home/multip:/bin/bash""",
                    filename='/etc/passwd')

            elif 'etc/shadow' in clean_path:
                return render_template('login.html',
                    file_content="cat: /etc/shadow: Permission denied",
                    filename='/etc/shadow')

            elif 'home/achu' in clean_path:
                if 'shell.txt' in clean_path:
                    return render_template('login.html',
                        file_content="Try the terminal at /shell_terminal",
                        filename='/home/achu/shell.txt')
                else:
                    return render_template('login.html',
                        file_content="total 12\ndrwxr-x--- 2 achu achu 4096 Jan  1 00:00 .\ndrwxr-xr-x 4 root root 4096 Jan  1 00:00 ..\n-rw-r--r-- 1 achu achu   15 Jan  1 00:00 shell.txt\n-rw-r----- 1 root achu   50 Jan  1 00:00 flag.png\n-rw-r--r-- 1 achu achu  100 Jan  1 00:00 .bashrc",
                        filename='/home/achu/')
        else:
            return render_template('login.html',
                error_msg=f"Error: {error}")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and users[username] == password:
            session['username'] = username
            session['current_dir'] = '/home/achu'
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login', error='/var/www/html/ctf/error.log'))

    return render_template('login.html')

@app.route('/shell_terminal')
def terminal():
    return render_template('terminal.html')

@app.route('/execute', methods=['POST'])

def execute_command():
    cmd = request.form.get('command', '').strip()
    current_dir = get_current_dir()
    username = session.get('username', 'user')

    # Initialize response
    response = ""

    # Parse command
    parts = cmd.split()
    if not parts:
        return ""

    command = parts[0]
    args = parts[1:] if len(parts) > 1 else []

    # Handle commands
    if command == 'ls':
        flags = []
        path = current_dir

        # Parse flags and path
        for arg in args:
            if arg.startswith('-'):
                flags.append(arg)
            else:
                path = arg if arg.startswith('/') else current_dir + '/' + arg

        if '-la' in flags or '-l' in flags or '-al' in flags:
            if path in filesystem and filesystem[path]['type'] == 'dir':
                response = f"total {len(filesystem[path]['contents'])}\n"
                for item in filesystem[path]['contents']:
                    item_path = path + '/' + item if path != '/' else '/' + item
                    if item_path in filesystem:
                        perm = filesystem[item_path]['permissions']
                        response += f"{perm} 2 {username} {username} 4096 Jan  1 00:00 {item}\n"
                    else:
                        response += f"-rw-r--r-- 1 {username} {username} 100 Jan  1 00:00 {item}\n"
            else:
                response = f"ls: cannot access '{path}': No such file or directory\n"
        else:
            if path in filesystem and filesystem[path]['type'] == 'dir':
                response = '  '.join(filesystem[path]['contents']) + '\n'
            else:
                response = f"ls: cannot access '{path}': No such file or directory\n"

    elif command == 'cd':
        if not args:
            new_dir = '/home/achu'
        else:
            target = args[0]
            if target == '~':
                new_dir = '/home/achu'
            elif target.startswith('/'):
                new_dir = target
            elif target == '..':
                # Go up one directory
                if current_dir == '/':
                    new_dir = '/'
                else:
                    new_dir = '/'.join(current_dir.split('/')[:-1])
                    if new_dir == '':
                        new_dir = '/'
            else:
                new_dir = current_dir + '/' + target if current_dir != '/' else '/' + target

        # Validate directory exists
        if new_dir in filesystem and filesystem[new_dir]['type'] == 'dir':
            set_current_dir(new_dir)
            response = ""
        else:
            response = f"bash: cd: {args[0]}: No such file or directory\n"

    elif command == 'pwd':
        response = current_dir + '\n'

    elif command == 'whoami':
        response = username + '\n'

    elif command == 'cat':
        if not args:
            response = "cat: missing operand\n"
        else:
            file_path = args[0] if args[0].startswith('/') else current_dir + '/' + args[0]

            if file_path == '/home/achu/shell.txt':
                response = "Try the terminal at /shell_terminal"
            elif file_path == '/home/achu/flag.png':
                if username == 'achu':
                    response = f"Flag: {FLAG}\n"
                else:
                    response = "cat: flag.png: Permission denied\n"
            elif file_path == '/etc/passwd':
                response = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
achu:x:1000:1000::/home/achu:/bin/bash
admin:x:1001:1001::/home/admin:/bin/bash
multip:x:1002:1002::/home/multip:/bin/bash\n"""
            elif file_path == '/etc/shadow':
                response = "cat: /etc/shadow: Permission denied\n"
            else:
                response = f"cat: {args[0]}: No such file or directory\n"

    elif command == 'sudo':
        if len(args) == 0:
            response = "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\nusage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\nusage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]\nusage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] file ...\n"
        elif args[0] == '-l':
            response = "Matching Defaults entries for achu on this host:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\nUser achu may run the following commands on this host:\n    (root) NOPASSWD: /usr/bin/cat\n"
        elif args[0] == 'cat' and len(args) > 1:
            if args[1] == '/etc/shadow':
                response = f"""root:*:19448:0:99999:7:::
daemon:*:19448:0:99999:7:::
bin:*:19448:0:99999:7:::
sys:*:19448:0:99999:7:::
achu:$y$j9T$oxKFK218Sy2095bIO2W00/$iQNMW2IWMBu.1va3/vPpoxn8nmF9kvvzP4fy5gEHTz9:20457:0:99999:7:::
admin:$6$salt123$V7L8kz8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z:19448:0:99999:7:::
multip:$6$salt456$a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6:19448:0:99999:7:::\n"""
            elif args[1] == '/etc/passwd':
                response = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
achu:x:1000:1000::/home/achu:/bin/bash
admin:x:1001:1001::/home/admin:/bin/bash
multip:x:1002:1002::/home/multip:/bin/bash\n"""
            else:
                response = f"sudo: cat: command not found\n"
        else:
            response = f"sudo: {args[0]}: command not found\n"

    elif command == 'help' or command == '--help':
        response = """Available commands:
  ls [dir]       - list directory contents
  cd [dir]       - change directory
  pwd            - print working directory
  cat [file]     - display file contents
  whoami         - display current user
  sudo [command] - execute command as superuser
  clear          - clear terminal screen
  help           - show this help message\n"""

    elif command == 'clear':
        response = "\033[H\033[2J"  # ANSI escape codes for clearing

    else:
        response = f"bash: {command}: command not found\n"

    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
