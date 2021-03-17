# Phorcys
Capstone project for using Reinforcement Learning to conduct intelligent penetration tests.

## Abstract (draft)

Penetration testing is a form of ethical hacking where a simulated attack is performed against a computer network to find possible attack vectors. Due to the complexity of penetration testing, it is commonly done manually by trained cybersecurity professionals. Additionally, the amount of time it takes to conduct a penetration test results in high costs, and the large scope of these assessments can lead to human errors that can result in missed vulnerabilities. Our project, named Phorcys, is designed to conduct the whole cyber kill-chain to report strengths and weaknesses within a network with the goal of simulating a real world attack without the need for a security professional. Phorcys utilizes machine learning to automate the process of penetration testing; it is able to conduct simulated penetration tests on its own, and can find new possible attack vectors by self learning. The number of vulnerabilities discovered each day is increasing which is why normal automation cannot suffice. Therefore, Phorcys’ use of machine learning provides companies with a trivial and free approach to conduct high quality penetration tests. At a high-level, Phorcys will start with a user who tells the system the scope of the attack. It will then perform reconnaissance that will be fed into the machine learning model for the current targets. The model will then send commands to the exploitation system, execute commands, and send the results back to the model. After successfully conducting the assessment, Phorcys concludes by generating a report of the penetration test.


### Sources

> - [What's New in the 2020 Cost of a Data Breach Report](https://securityintelligence.com/posts/whats-new-2020-cost-of-a-data-breach-report/)
