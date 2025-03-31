# My eJPTv2 Certification Experience

## Table of Contents
- [What is eJPTv2?](#what-is-ejptv2)
- [My Preparation Journey](#my-preparation-journey)
  - [The Official INE Course (PTSv2)](#the-official-ine-course-ptsv2)
  - [Additional Practice with CTF Labs](#additional-practice-with-ctf-labs)
- [The Exam Experience](#the-exam-experience)
- [Career Impact](#career-impact)
- [Was It Worth It?](#was-it-worth-it)
- [Tips for Passing eJPTv2 on Your First Attempt](#tips-for-passing-ejptv2-on-your-first-attempt)
- [Resources That Helped Me Succeed](#resources-that-helped-me-succeed)
  - [Cheatsheets](#cheatsheets)
  - [Note-Taking Template](#note-taking-template)

## What is eJPTv2?

The eJPTv2 (eLearn Security Junior Penetration Tester version 2) is an entry-level penetration testing certification offered by INE at a cost of $250, though discounts are occasionally available. Upon purchase, you receive two exam attempts valid for 90 days.

This is a 100% practical, dynamic exam where you gain access to a virtual machine to perform a real penetration test. According to INE, this exam validates the knowledge and skills necessary to work as a junior penetration tester.

The certification recognizes skills in the following areas:
- IP Routing
- Basic scanning, enumeration, and exploitation of known ports and services
- Privilege escalation
- Basic pivoting and port forwarding
- Metasploit exploitation
- Information gathering

The exam consists of 35 questions to be answered within 48 hours, with a 70% passing score required. Some questions have dynamic answers that may change if you restart the virtual machine, so I recommend answering these questions immediately when you find them to avoid complications.

## My Preparation Journey

### The Official INE Course (PTSv2)

The PTSv2 course provided by INE with the exam purchase is comprehensive and covers everything needed to pass the exam. It includes video content and practical labs.

The course is divided into four modules:
1. **Assessment Methodologies** - Web reconnaissance, footprinting, whois enumeration, DNS reconnaissance, firewall and WAF identification, subdomain enumeration with sublist3r, Google dorking, and port discovery with nmap.
2. **Host and Network Auditing** - Tools for auditing networks and services, enumeration of SMB, FTP, SSH, HTTP, and SQL services.
3. **Host and Network Penetration Testing** - Exploiting known vulnerabilities in Windows and Linux, including Eternal Blue, WebDAV with Metasploit, SMB with PsExec, WinRM, and more.
4. **Web Application Penetration Testing** - Exploiting web vulnerabilities like SQL injection, XSS, and attacks on login pages.

Despite having experience with HTB machines, I found the course content easy to consume. The documentation on commands and tools proved very useful during the exam and helped me master the fundamentals of hacking that will make a difference in the long term.

### Additional Practice with CTF Labs

To expand my knowledge, I also practiced with various Capture The Flag (CTF) labs from platforms like:

**TryHackMe machines:**
- Blue
- Ice
- Blaster
- Pentesting Fundamentals
- Ignite
- Blog
- Startup
- Chill Hack
- Bolt
- VulnNet: Internal
- ColddBox: Easy

**HackTheBox machines:**
- Union
- Validation
- Return
- Goodgames

**VulnHub machines:**
- Dark Hole 1
- Dark Hole 2
- Symfonos 1
- Election 1

## The Exam Experience

The eJPTv2 exam provides a realistic penetration testing experience rather than just a CTF challenge. Instead of hunting for flags, you're conducting a proper penetration test in a professional environment. You're given access to a network where you must discover how many hosts are present and perform comprehensive testing on them.

I found this approach particularly valuable as it simulates real-world scenarios more accurately than traditional CTF challenges. Having to enumerate the network, discover hosts, and methodically work through the infrastructure gave me insight into how professional penetration tests are conducted.

The dynamic nature of some questions added an extra layer of challenge, requiring careful documentation throughout the process.

Although the exam allows up to 48 hours for completion, I managed to finish it in just 4-6 hours and achieved a score of 98%. This success was largely due to thorough preparation and the use of the cheatsheets and note-taking templates mentioned in the resources section below.

## Career Impact

Thanks to this certification, I secured my first job as a security analyst in a SOC (Security Operations Center). 

However, it's important to note that the certification alone wasn't enough. Your experience, profile, attitude, and how you present yourself all play crucial roles in the job search process. In my case, the certification helped validate the knowledge I had acquired over years of study.

When I tried to enter some companies as a junior pentester, this certification wasn't sufficient by itself. Industry professionals gave me two valuable pieces of advice:
1. It's easier to pivot to your preferred area once you're already in the cybersecurity sector. In my case, I have better chances of joining a red team if I pivot from a blue team position.
2. A certification alone doesn't guarantee anything—complement it with experience and personal projects.

## Was It Worth It?

Absolutely. The eJPTv2 is an ideal initial certification because it gives you first-hand experience with the reality of penetration testing. By testing in a real environment, you gain deep insights into how a penetration test would be conducted in a professional setting.

If you're planning to pursue higher-level certifications like eCCPTv2, eWPT, or OSCP, the eJPTv2 provides valuable experience with certification exams and helps prepare you mentally for future challenges.

One thing is clear: even though it's an entry-level certification, it demonstrates that having a solid methodology makes all the difference.

## Tips for Passing eJPTv2 on Your First Attempt

1. **Be patient** - Cybersecurity can be overwhelming due to the amount of information. You have 3 months to take the exam, so practice as much as possible, repeat the labs, and take detailed notes.

2. **Use multiple tools** - Don't rely on just one tool or the first result you get. Sometimes tools show incorrect or incomplete information. Compare results from different tools to ensure you have the correct answers.

3. **Master Metasploit** - The PTSv2 course teaches how to use Metasploit, which was essential for completing my exam.

4. **Use the questions as guidance** - Remember "Occam's Razor" - the simplest explanation is often correct. The exam questions are designed to help you, and the lab environment is meant to be hacked.

5. **Enumerate thoroughly** - Document everything you find. Remember this isn't a CTF but a professional penetration test simulation.

6. **Research and rest** - Read other eJPTv2 reviews, study cheatsheets, and create your own based on the PTSv2 information. Get a good night's sleep before the exam, try to work in an environment free from distractions, take breaks, and read the questions carefully.

## Resources That Helped Me Succeed

One of the key factors in my success was using well-organized resources for both preparation and during the exam itself. These resources not only helped me study efficiently but also allowed me to document findings methodically during the test, which contributed to my high score of 98% completed in just 4-6 hours (despite the 48-hour time allowance).

### Cheatsheets

I created and used comprehensive cheatsheets that covered all the essential commands and techniques needed for the exam:

1. **eJPTv2 Cheatsheet (Spanish)**  
   [https://www.notion.so/Cheatsheet-para-el-eJPTv2-e9ac88d9b19c416d88ecc190d992eeb8](https://www.notion.so/Cheatsheet-para-el-eJPTv2-e9ac88d9b19c416d88ecc190d992eeb8)  
   This cheatsheet covers fundamental commands and techniques in Spanish.

2. **Complete eJPTv2 Cheatsheet**  
   [https://www.notion.so/eJPTv2-Complete-Cheat-sheet-7a9012246bec4d37a9aa3a31f57934cc](https://www.notion.so/eJPTv2-Complete-Cheat-sheet-7a9012246bec4d37a9aa3a31f57934cc)  
   A comprehensive collection of commands, techniques, and approaches organized by category.

### Note-Taking Template

Proper documentation is crucial during penetration testing. I used a specially designed template to keep track of all my findings during the exam:

**eJPTv2 Notes Template**  
[https://www.notion.so/Plantilla-apuntes-eJPTv2-dff014aaef454c0d92b15f0d84dd181a](https://www.notion.so/Plantilla-apuntes-eJPTv2-dff014aaef454c0d92b15f0d84dd181a)

This template helped me organize information about:
- Network topology
- Discovered hosts
- Open ports and services
- Vulnerabilities
- Exploitation paths
- Credentials found
- Post-exploitation findings

Using this structured approach to documentation allowed me to easily refer back to earlier findings, track my progress, and quickly locate information needed to answer exam questions. I highly recommend creating or using a similar template for your own exam preparation and execution.
