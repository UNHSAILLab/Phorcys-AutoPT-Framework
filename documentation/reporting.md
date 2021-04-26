# Reporting System
The Phorcys reporting system is called after the program runs
It will take data in the form of nested dictionaries.
The data is in this form:
1. Dictionary of Hosts
2. Dictionary of Ports
3. Dictionary of Exploits, Accesslevel, and Output.

```json
{
    '192.168.0.1': {
        22: {
            'exploit':
            'accesslevel':
            'output':
        },
        44:{
            'exploit':
            'accesslevel':
            'output':
        }
    }
}
```