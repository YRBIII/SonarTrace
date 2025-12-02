# **SonarTrace – Contributions**

This page explains what each of us worked on for the final project.

---

## **Yung

I worked on the project's backend. So, my role was to ensure that the program could understand targets, filter out everything that shouldn't be scanned, and execute Nmap properly. I also handled the parts that prepare the scan, run it, and deal with any mistakes that may occur.

I configured the target parser, CIDR handling (Classless Inter-Domain Routing), DNS safety checks (Domain Name System), and scanning engine, which delivers everything to Nmap.  I also configured all logging and error handling.  In addition, I set up the GitHub repository and the project folder structure.

### **Files I worked on**

* `targets.py`
* `utils.py`
* `enumerator.py`
* `__main__.py`
* `exceptions.py`
* `logger_setup.py`
* `config.py`
* `result_objects.py`

---
