# Setting up Python

Phorcys can only be verified to work on Python 3.7.10 this is due to some external dependencies that work on this version. However, in the future this may change because of less dependencies.

Once python is installed a virtual environment is highly recommended to be setup. In our experiment this was done by being in the folders directory using the the following command:

```bash
$ python3 -m venv .
```

The virtual environment can then be accessed and deactivated by doing:

```bash
$ . bin/activate
$ deactivate
```

While in the virtualenv to install all dependencies do the following:

```bash
$ pip install -r requirements.txt
```
# Command line arguments

At minimum, the scope of the attack will need to be provided. While domain names may, work only IPv4 addresses have been tested currently. All command line options

```bash
usage: Phorcys [-h] [-s] [-m] [-j [JSON]] [-i [ITERATIONS]] [-a [ACTIONS]]
               [-w [WORKERS]] [-l [LOGLEVEL]]
               target

============================================================
               ___  __                   
              / _ \/ /  ___  __________ _____
             / ___/ _ \/ _ \/ __/ __/ // (_-<
            /_/  /_//_/\___/_/  \__/\_, /___/
                                   /___/

============================================================


Automated Penetration Testing via Deep Reinforcement Learning

positional arguments:
  target                Scope of the Penetration Test (IPv4 Address or CIDR
                        Notation)

optional arguments:
  -h, --help            show this help message and exit
  -s, --new_scan        Scan with OWASPNettacker or use pre-existing data scan
                        data
  -m, --mute_banner     Hide amazing phorcys banner
  -j [JSON], --json_file [JSON]
                        use json file instead of nettacker data.
  -i [ITERATIONS], --iterations [ITERATIONS]
                        Define number of training iterations for RL agent
                        (Default: 100000)
  -a [ACTIONS], --actions_per_target [ACTIONS]
                        Define training number of actions per host that is
                        allowed. (Default: 5)
  -w [WORKERS], --workers [WORKERS]
                        Define number of Workers for training.
  -l [LOGLEVEL], --log [LOGLEVEL]
```

Example usage:

```bash
$ python3 main.py 192.168.1.100,192.168.1.200,192.168.1.201,192.168.1.183,192.168.1.231,192.168.1.79,192.168.1.115 -j temp.json -a 7 -w 10
```


# Tensorboard
Tensorboard can be setup properly by using the tensorboard script provided. 

# Additional Notes
When training over SSH if session is closed it will kill the program. Therefore we recommend using tmux to detach the session from the user this can be done using the following:

```bash
tmux 
```

Once in the tmux session run the relevant command to start training. Once it has started, Press Ctrl+B then D to detach the terminal. If you type exit in a tmux session it will kill that session. To reconnect to it do the following:

```bash
tmux ls # this lists the sessions
tmux attach -t <sessionid> 
```

When using ray it will open ports to view the status of the training. It can be viewed at by default 127.0.0.1:8265