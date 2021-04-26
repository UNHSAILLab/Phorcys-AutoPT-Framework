# Setting up Nettacker and Metasploit RPC APIs
## Metasploit RPC API
To start the Metasploit RPC API, you need to define the password that is used to connect to API by running the following commands within the machine hosting the server:
```bash
msfrpcd -P 'PASSWORD' -S
```
Once you are done with running your code, or you need to reboot the API, you can shut it down by killing the process using the commands:
```bash
ps aux | grep msfrpcd
kill -9 'msfrpcd process number'
```
## Nettacker API
To start the Nettacker API you will need to clone the repository from https://github.com/OWASP/Nettacker. Once the repository is closed, you will need to enter directory and run the docker container with the commands:
```bash
docker compose up
```
## Configuration File - (Config.ini)
Once the APIs are up and running, you will need to modify the Configuration file to reflect the proper IP Address for the API servers. This will be the public or localhost IP address of the machine running the Metasploit and Nettacker APIs depending on the location of the code and your preference.
```bash
[Metasploit]
ip = 'Enter IP ADDRESS (XXX.XXX.XXX.XXX)'
port = 55553
password = 'Password'
[Nettacker]
ip = 'IP ADDRESS (XXX.XXX.XXX.XXX)'
port = 5000
key = 'NETTACKER API KEY'
```