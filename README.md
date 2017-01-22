# SystemTap
SystemTap provides free software (GPL) infrastructure to simplify the gathering of information about the running Linux system.

Tested using 3.13.0-107-generic, systemtap 2.3.

## Using SystemTap
### Installation and Setup
#### Installing SystemTap
On Ubuntu or Debian, use "apt-get install systemtap".

Note that to run most examples you will need kernel debug symbols matching your kernel; see below how to download it. Of course, if you built your own kernel, you'd get the debug symbols from your compiler; on Debian or Ubuntu you just download a debug build of the kernel and trust that is matches the binary kernel included in your distribution.

#### Getting kernel debuginfo symbols
(from https://wiki.edubuntu.org/Kernel/Systemtap )

My script based on the above:
```
#!/bin/bash
codename=$(lsb_release -c | awk  '{print $2}')
sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename}      main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ECDCAD72428D7C01
sudo apt-get update
sudo apt-get install linux-image-$(uname -r)-dbgsym
```

### Running SystemTap Scripts
The `stap` command reads probing instructions from a SystemTap script, translates these instructions into C code, builds a kernel module, and loads it into the running Linux kernel. 
```
Usage: stap [options] FILE         Run script in file.

Options:
   -v         add verbosity to all passes
```
To disable secure boot: BIOS Setup -> Secure Boot -> Secure Boot Enable -> Disabled
## Understanding How SystemTap Works
SystemTap allows users to write and reuse simple scripts to deeply examine the activities of a running Linux system. These scripts can be designed to extract data, filter it, and summarize it quickly (and safely), enabling the diagnosis of complex performance (or even functional) problems.

The essential idea behind a SystemTap script is to name *events*, and to give them handlers. When SystemTap runs the script, SystemTap monitors for the event; once the event occurs, the Linux kernel then runs the handler as a quick sub-routine, then resumes.

### SystemTap Scripts
SystemTap scripts are made up of two components: events and handlers. Once a SystemTap session is underway, SystemTap monitors the operating system for the specified events and executes the handlers as they occur.

Note: An event and its corresponding handler is collectively called a probe. A SystemTap script can have multiple probes.

SystemTap scripts use the file extension **.stp**, and contains probes written in the following format: 
```
probe event {statements}
```
Each probe has a corresponding statement block. This statement block is enclosed in braces (**{** **}**) and contains the statements to be executed per event.

## Useful SystemTap Scripts

### Network

The following sections showcase scripts that trace network-related functions and build a profile of network activity.

#### Network Profiling

This section describes how to profile network activity. nettop.stp provides a glimpse into how much network traffic each process is generating on a machine.

```
#! /usr/bin/env stap

global ifxmit, ifrecv
global ifmerged

probe netdev.transmit
{
  ifxmit[pid(), dev_name, execname(), uid()] <<< length
}

probe netdev.receive
{
  ifrecv[pid(), dev_name, execname(), uid()] <<< length
}

function print_activity()
{
  printf("%5s %5s %-7s %7s %7s %7s %7s %-15s\n",
         "PID", "UID", "DEV", "XMIT_PK", "RECV_PK",
         "XMIT_KB", "RECV_KB", "COMMAND")

  foreach ([pid, dev, exec, uid] in ifrecv) {
    ifmerged[pid, dev, exec, uid] += @count(ifrecv[pid,dev,exec,uid]);
  }
  foreach ([pid, dev, exec, uid] in ifxmit) {
    ifmerged[pid, dev, exec, uid] += @count(ifxmit[pid,dev,exec,uid]);
  }
  foreach ([pid, dev, exec, uid] in ifmerged-) {
    n_xmit = @count(ifxmit[pid, dev, exec, uid])
    n_recv = @count(ifrecv[pid, dev, exec, uid])
    printf("%5d %5d %-7s %7d %7d %7d %7d %-15s\n",
           pid, uid, dev, n_xmit, n_recv,
           n_xmit ? @sum(ifxmit[pid, dev, exec, uid])/1024 : 0,
           n_recv ? @sum(ifrecv[pid, dev, exec, uid])/1024 : 0,
           exec)
  }

  print("\n")

  delete ifxmit
  delete ifrecv
  delete ifmerged
}

probe timer.ms(5000), end, error
{
  print_activity()
}
```
nettop.stp tracks which processes are generating network traffic on the system, and provides the following information about each process:
- **PID** — the ID of the listed process.
- **UID** — user ID. A user ID of 0 refers to the root user.
- **DEV** — which ethernet device the process used to send / receive data (for example, eth0, eth1)
- **XMIT_PK** — number of packets transmitted by the process
- **RECV_PK** — number of packets received by the process
- **XMIT_KB** — amount of data sent by the process, in kilobytes
- **RECV_KB** — amount of data received by the service, in kilobytes

nettop.stp Sample Output
```
[...]
  PID   UID DEV     XMIT_PK RECV_PK XMIT_KB RECV_KB COMMAND
    0     0 eth0          0       5       0       0 swapper
11178     0 eth0          2       0       0       0 synergyc

  PID   UID DEV     XMIT_PK RECV_PK XMIT_KB RECV_KB COMMAND
 2886     4 eth0         79       0       5       0 cups-polld
11362     0 eth0          0      61       0       5 firefox
    0     0 eth0          3      32       0       3 swapper
 2886     4 lo            4       4       0       0 cups-polld
11178     0 eth0          3       0       0       0 synergyc

  PID   UID DEV     XMIT_PK RECV_PK XMIT_KB RECV_KB COMMAND
    0     0 eth0          0       6       0       0 swapper
 2886     4 lo            2       2       0       0 cups-polld
11178     0 eth0          3       0       0       0 synergyc
 3611     0 eth0          0       1       0       0 Xorg

  PID   UID DEV     XMIT_PK RECV_PK XMIT_KB RECV_KB COMMAND
    0     0 eth0          3      42       0       2 swapper
11178     0 eth0         43       1       3       0 synergyc
11362     0 eth0          0       7       0       0 firefox
 3897     0 eth0          0       1       0       0 multiload-apple
[...]
```