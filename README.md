# Phorcys - Intelligent Penetration Testing using Deep Reinforcement Learning

<p align="center">
  <img width="350px" height="350px" src="https://github.com/UNHSAILLab/Capstone-Automated-Penetration-Testing/blob/master/images/phorcys_cropped.png" />
</p>

Capstone project for using Reinforcement Learning to conduct intelligent penetration tests.

## Abstract

Penetration testing is a form of ethical hacking where an attack is performed against a computer network to find vulnerabilities. Due to the complexity of penetration testing, it is commonly done manually by trained cybersecurity professionals. Additionally, the lengthy amount of time it takes to conduct a penetration test results in high costs, and the large scope of these assessments can lead to human errors resulting in missed vulnerabilities. Our project, named Phorcys, is designed to conduct an automated real-world attack utilizing recent advances in machine learning to report strengths and weaknesses within a network. Phorcys utilizes deep Reinforcement Learning (RL) to automate the process of penetration testing. Once trained, The Phorcys RL agent can conduct penetration tests fully autonomously. Therefore, Phorcys’ use of deep RL provides companies with a straightforward and cost effective approach to conduct high-quality and frequent penetration tests. At a high-level, Phorcys will start with a user who tells the agent the scope of the attack. It will then perform reconnaissance that will be ingested into the deep RL model for the given targets. The model will decide on what exploits to leverage in the process, and executes those exploits to compromise the target. After successfully conducting the assessment, Phorcys concludes by automatically generating a report of the penetration test.

## Architecture

<p align="center">
  <img src="https://github.com/UNHSAILLab/Capstone-Automated-Penetration-Testing/blob/master/images/phorcys_arch.png">
</p>

## Documentation to Setup Phorcys there are several parts to it Please following in order

1. [AWS CloudFormation](documentation/cloud-formation.md)
2. [Custom AMIs](documentation/custom-ami.md)
3. [Setting up Python](documentation/python.md)
4. [Services to Setup](documentation/services.md)
5. [Report Generation Information](documentation/reporting.md)


### Sources

> - [What's New in the 2020 Cost of a Data Breach Report](https://securityintelligence.com/posts/whats-new-2020-cost-of-a-data-breach-report/)
